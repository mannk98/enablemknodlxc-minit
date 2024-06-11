/*
Copyright © 2024 mannk khacman98@gmail.com
*/
package cmd

import (
	"fmt"
	"net/url"
	"os"
	"runtime"
	"strings"

	"github.com/beevik/etree"
	"github.com/digitalocean/go-libvirt"
	"github.com/mannk98/goutils/utils"
	log "github.com/sirupsen/logrus"

	"github.com/sonnt85/gosutils/sched"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var (
	cfgFile        string
	Logger         = log.New()
	LogLevel       = log.DebugLevel
	LogFile        = "enablemknodlxc.log"
	cfgFileDefault = ".enablemknodlxc"
)

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:   "enablemknodlxc",
	Short: "A brief description of your application",
	Long: `A longer description that spans multiple lines and likely contains
examples and usage of using your application. For example:

Cobra is a CLI library for Go that empowers applications.
This application is a tool to generate the needed files
to quickly create a Cobra application.`,
	// Uncomment the following line if your bare application
	// has an action associated with it:
	Run: rootRun,
}

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {
	err := rootCmd.Execute()
	if err != nil {
		os.Exit(1)
	}
}

func init() {
	utils.InitLogger(LogFile, Logger, LogLevel)
	cobra.OnInitialize(initConfig)

	// Here you will define your flags and configuration settings.
	// Cobra supports persistent flags, which, if defined here,
	// will be global for your application.

	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file (default is $HOME/.enablemknodlxc.yaml)")

	// Cobra also supports local flags, which will only run
	// when this action is called directly.
	rootCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
}

// initConfig reads in config file and ENV variables if set.
func initConfig() {
	if cfgFile != "" {
		// Use config file from the flag.
		viper.SetConfigFile(cfgFile)
	} else {
		// Find home directory.
		home, err := os.UserHomeDir()
		if err != nil {
			Logger.Error(err)
			os.Exit(1)
		}

		cfgFile = cfgFileDefault
		// Search config in home directory with name ".enablemknodlxc" (without extension).
		viper.AddConfigPath(home)
		viper.AddConfigPath("./")
		viper.SetConfigType("toml")
		viper.SetConfigName(cfgFile)
	}

	viper.AutomaticEnv() // read in environment variables that match

	if err := viper.ReadInConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); ok {
			log.Error("config.toml file at ./ folder is not exist. Create it first.")
		} else {
			Logger.Error(err)
		}
	} else {
		Logger.Info("Using config file:", viper.ConfigFileUsed())
	}
}

func rootRun(cmd *cobra.Command, args []string) {
	job := func(sched *sched.Job) {
		domains, connect, err := GetListActiveDomainsLxc()
		if err != nil {
			Logger.Error("Cant get domain: ", err)
		}
		for _, domain := range domains {
			fmt.Println(domain.Name)
			isEnableKnod, xmldump, err := CheckXMLIsEnableKnod(connect, domain)
			if err != nil {
				Logger.Errorf("Check XML of %s virtual lxc: %v", domain.Name, err)
				continue
			}
			if isEnableKnod {
				//Logger.Infof("%s already had knode enable ", domain.Name)
				continue
			}
			xmlafterenableknod, err := XMLEnableKnod(xmldump)
			if err != nil {
				Logger.Error("Error add knode feature in  XML: ", err)
			}
			//fmt.Println(xmlafterenableknod)
			added_knod_domain, err := connect.DomainDefineXMLFlags(xmlafterenableknod, libvirt.DomainDefineValidate)
			if err != nil {
				Logger.Errorf("Error when define new domain %s with knod enable: ", domain.Name)
			} else {
				err := connect.DomainReboot(added_knod_domain, libvirt.DomainRebootDefault)
				if err != nil {
					Logger.Errorf("Error when reboot %s", domain.Name)
				} else {
					Logger.Infof("Success reboot and enable knod capabilities for domain: %s", added_knod_domain.Name)
				}
			}
		}

		if err = connect.Disconnect(); err != nil {
			Logger.Errorf("failed to disconnect libvird: %v", err)
		}
	}
	sched.Every(10).ESeconds().Run(job)
	// Keep the program from not exiting.
	runtime.Goexit()
}

func GetListActiveDomainsLxc() ([]libvirt.Domain, *libvirt.Libvirt, error) {
	uri, _ := url.Parse("lxc:///")
	connect, err := libvirt.ConnectToURI(uri)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to connect: %v", err)
	}

	/* 	v, err := l.ConnectGetLibVersion()
	   	if err != nil {
	   		log.Fatalf("failed to retrieve libvirt version: %v", err)
	   	}
	   	fmt.Println("Version:", v) */

	flags := libvirt.ConnectListDomainsActive //| libvirt.ConnectListDomainsInactive
	domains, _, err := connect.ConnectListAllDomains(1, flags)
	if err != nil {
		return nil, connect, fmt.Errorf("failed to retrieve domains: %v", err)
	}
	return domains, connect, err
}

func CheckXMLIsEnableKnod(connect *libvirt.Libvirt, domain libvirt.Domain) (bool, string, error) {
	xmldump, err := connect.DomainGetXMLDesc(domain, libvirt.DomainXMLSecure)
	if err != nil {
		return false, xmldump, fmt.Errorf("can't get xml of domain %s %v", domain.Name, err)
	}
	if !strings.Contains(xmldump, "mknod") {
		return false, xmldump, err
	}
	return true, xmldump, err
}

func XMLEnableKnod(xmlData string) (string, error) {
	doc := etree.NewDocument()
	if err := doc.ReadFromString(xmlData); err != nil {
		return "", fmt.Errorf("read xml data err: %v", err)
	}

	// Find the <features> element
	features := doc.FindElement("//features")
	if features == nil {
		return "", fmt.Errorf("missing <features> element")
	}

	// Create the new <capabilities> element
	capabilities := etree.NewElement("capabilities")
	capabilities.CreateAttr("policy", "allow")
	mknod := capabilities.CreateElement("mknod")
	mknod.CreateAttr("state", "on")

	// Add the new element to <features>
	features.AddChild(capabilities)

	// Output the modified XML
	doc.Indent(2)
	xmlOutput, err := doc.WriteToString()
	if err != nil {
		return "", fmt.Errorf("error when write xml string: %v", err)
	}
	return xmlOutput, err
}
