package cmd

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/spf13/cobra"
	"github.com/demianrey/Bugdetect/pkg/proxydetector"
	"github.com/demianrey/Bugdetect/pkg/snidetector"
)

var (
	flagOutput    string
	flagInterface string
	flagTimeout   int
	flagDuration  int
	flagSNI       bool
	flagProxy     string
)

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:   "bugdetect",
	Short: "A real-time network bug detection tool",
	Long: `Bugdetect is a tool for real-time detection of network vulnerabilities,
focusing primarily on SNI (Server Name Indication) bugs in TLS/SSL connections.

This tool requires root/administrator privileges to capture network traffic.`,
	Run: runDetect,
}

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

func init() {
	// Flags for the root command
	rootCmd.Flags().StringVarP(&flagOutput, "output", "o", "", "output file for detected bugs")
	rootCmd.Flags().StringVarP(&flagInterface, "interface", "i", "", "network interface to monitor")
	rootCmd.Flags().IntVar(&flagTimeout, "timeout", 5, "connection timeout in seconds")
	rootCmd.Flags().IntVar(&flagDuration, "duration", 0, "duration to run detector in minutes (0 for indefinite)")
	rootCmd.Flags().BoolP("version", "v", false, "Print the version number of Bugdetect")
	rootCmd.Flags().BoolVar(&flagSNI, "sni", false, "Enable SNI vulnerability detection")
	rootCmd.Flags().StringVar(&flagProxy, "proxy", "", "HTTP proxy to use for proxy detection (format: http://domain:port)")

	rootCmd.MarkFlagRequired("output")
}

func runDetect(cmd *cobra.Command, args []string) {
	// Check if running as root
	if os.Geteuid() != 0 {
		fmt.Println("This command requires root privileges. Please run with sudo.")
		os.Exit(1)
	}

	// Check if at least one detection mode is enabled
	if !flagSNI && flagProxy == "" {
		fmt.Println("Error: At least one detection mode must be enabled (--sni or --proxy)")
		os.Exit(1)
	}

	// Create output file
	outputFile, err := os.Create(flagOutput)
	if err != nil {
		fmt.Printf("Error creating output file: %s\n", err.Error())
		os.Exit(1)
	}
	defer outputFile.Close()

	// Set up context with cancellation
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Set up signal handling for graceful shutdown
	signalChan := make(chan os.Signal, 1)
	signal.Notify(signalChan, syscall.SIGINT, syscall.SIGTERM)
	
	go func() {
		<-signalChan
		fmt.Println("\nReceived interrupt signal. Shutting down...")
		cancel()
		
		// Add a second signal handler for force exit
		forceSignal := make(chan os.Signal, 1)
		signal.Notify(forceSignal, syscall.SIGINT, syscall.SIGTERM)
		
		// If user presses Ctrl+C again, force exit
		select {
		case <-forceSignal:
			fmt.Println("Force exiting...")
			os.Exit(0)
		case <-time.After(5 * time.Second):
			fmt.Println("Shutdown taking too long, force exiting...")
			os.Exit(0)
		}
	}()

	// Set duration if specified
	if flagDuration > 0 {
		durationCtx, durationCancel := context.WithTimeout(ctx, time.Duration(flagDuration)*time.Minute)
		defer durationCancel()
		ctx = durationCtx
	}

	// Only allow one type of detection to prevent device lockups
	if flagSNI && flagProxy != "" {
		fmt.Println("Error: Only one detection mode can be enabled at a time (--sni or --proxy)")
		os.Exit(1)
	}

	// Run SNI detection if enabled
	if flagSNI {
		// Configure the detector
		config := snidetector.Config{
			Interface:  flagInterface,
			OutputFile: outputFile,
			Timeout:    time.Duration(flagTimeout) * time.Second,
		}

		// Start the detector
		detector := snidetector.NewDetector(config)
		fmt.Println("Starting SNI bug detection. Press Ctrl+C to stop.")
		err = detector.Start(ctx)
		if err != nil {
			fmt.Printf("Error during detection: %s\n", err.Error())
			os.Exit(1)
		}
	}

	// Run Proxy detection if enabled
	if flagProxy != "" {
		// Configure the detector
		config := proxydetector.Config{
			Interface:  flagInterface,
			OutputFile: outputFile,
			Timeout:    time.Duration(flagTimeout) * time.Second,
			ProxyURL:   flagProxy,
		}

		// Start the detector
		detector, err := proxydetector.NewDetector(config)
		if err != nil {
			fmt.Printf("Error creating proxy detector: %s\n", err.Error())
			os.Exit(1)
		}
		
		fmt.Println("Starting Proxy bug detection. Press Ctrl+C to stop.")
		err = detector.Start(ctx)
		if err != nil {
			fmt.Printf("Error during detection: %s\n", err.Error())
			os.Exit(1)
		}
	}

	fmt.Println("Detection completed. Results saved to", flagOutput)
}