// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package instrumentation

import (
	"fmt"
	"sort"
	"strings"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	"k8s.io/utils/strings/slices"

	"github.com/aws/amazon-cloudwatch-agent-operator/internal/naming"
	"github.com/aws/amazon-cloudwatch-agent-operator/pkg/constants"
)

const (
	// CloudWatch agent service endpoints
	cloudwatchAgentStandardEndpoint = "cloudwatch-agent.amazon-cloudwatch"
	cloudwatchAgentWindowsEndpoint  = "cloudwatch-agent-windows-headless.amazon-cloudwatch.svc.cluster.local"
	cloudwatchAgentPort             = "4316"
)

var defaultSize = resource.MustParse("200Mi")

// Calculate if we already inject InitContainers.
func isInitContainerMissing(pod corev1.Pod, containerName string) bool {
	for _, initContainer := range pod.Spec.InitContainers {
		if initContainer.Name == containerName {
			return false
		}
	}
	return true
}

// Checks if Pod is already instrumented by checking Instrumentation InitContainer presence.
func isAutoInstrumentationInjected(pod corev1.Pod) bool {
	for _, cont := range pod.Spec.InitContainers {
		if slices.Contains([]string{
			dotnetInitContainerName,
			javaInitContainerName,
			nodejsInitContainerName,
			pythonInitContainerName,
			apacheAgentInitContainerName,
			apacheAgentCloneContainerName,
		}, cont.Name) {
			return true
		}
	}

	for _, cont := range pod.Spec.Containers {
		// Go uses a sidecar
		if cont.Name == sideCarName {
			return true
		}

		// This environment variable is set in the sidecar and in the
		// collector containers. We look for it in any container that is not
		// the sidecar container to check if we already injected the
		// instrumentation or not
		if cont.Name != naming.Container() {
			for _, envVar := range cont.Env {
				if envVar.Name == constants.EnvNodeName {
					return true
				}
			}
		}
	}
	return false
}

// Look for duplicates in the provided containers.
func findDuplicatedContainers(ctrs []string) error {
	// Merge is needed because of multiple containers can be provided for single instrumentation.
	mergedContainers := strings.Join(ctrs, ",")

	// Split all containers.
	splitContainers := strings.Split(mergedContainers, ",")

	countMap := make(map[string]int)
	var duplicates []string
	for _, str := range splitContainers {
		countMap[str]++
	}

	// Find and collect the duplicates
	for str, count := range countMap {
		// omit empty container names
		if str == "" {
			continue
		}

		if count > 1 {
			duplicates = append(duplicates, str)
		}
	}

	if duplicates != nil {
		sort.Strings(duplicates)
		return fmt.Errorf("duplicated container names detected: %s", duplicates)
	}

	return nil
}

// Return positive for instrumentation with defined containers.
func isInstrWithContainers(inst instrumentationWithContainers) int {
	if inst.Containers != "" {
		return 1
	}

	return 0
}

// Return positive for instrumentation without defined containers.
func isInstrWithoutContainers(inst instrumentationWithContainers) int {
	if inst.Containers == "" {
		return 1
	}

	return 0
}

func volumeSize(quantity *resource.Quantity) *resource.Quantity {
	if quantity == nil {
		return &defaultSize
	}
	return quantity
}

// containsCloudWatchAgent checks if the endpoint contains CloudWatch agent service endpoints
func containsCloudWatchAgent(endpoint string) bool {
	// Check for standard CloudWatch agent endpoint with port 4316
	standardEndpoint := cloudwatchAgentStandardEndpoint + ":" + cloudwatchAgentPort
	// Check for Windows headless service endpoint with port 4316
	windowsEndpoint := cloudwatchAgentWindowsEndpoint + ":" + cloudwatchAgentPort

	return strings.Contains(endpoint, standardEndpoint) || strings.Contains(endpoint, windowsEndpoint)
}

// getEnvValue returns the value of an environment variable from the container's env list
func getEnvValue(envs []corev1.EnvVar, name string) string {
	for _, env := range envs {
		if env.Name == name {
			return env.Value
		}
	}
	return ""
}

// isApplicationSignalsExplicitlyEnabled checks if OTEL_AWS_APPLICATION_SIGNALS_ENABLED is explicitly set to true
func isApplicationSignalsExplicitlyEnabled(envs []corev1.EnvVar) bool {
	value := getEnvValue(envs, "OTEL_AWS_APPLICATION_SIGNALS_ENABLED")
	return strings.EqualFold(value, "true")
}

// isApplicationSignalsExplicitlyDisabled checks if OTEL_AWS_APPLICATION_SIGNALS_ENABLED is explicitly set to false or not set at all
func isApplicationSignalsExplicitlyDisabled(envs []corev1.EnvVar) bool {
	value := getEnvValue(envs, "OTEL_AWS_APPLICATION_SIGNALS_ENABLED")
	// Consider it disabled if explicitly set to "false" or not set at all (empty string)
	return strings.EqualFold(value, "false") || value == ""
}

// shouldInjectADOTSDK determines if the ADOT SDK should be injected based on existing environment variables
func shouldInjectADOTSDK(envs []corev1.EnvVar) bool {
	// Check OTEL_EXPORTER_OTLP_ENDPOINT
	otlpEndpoint := getEnvValue(envs, "OTEL_EXPORTER_OTLP_ENDPOINT")
	if otlpEndpoint != "" && !containsCloudWatchAgent(otlpEndpoint) {
		// If Application Signals is explicitly disabled, don't inject
		if isApplicationSignalsExplicitlyDisabled(envs) {
			return false
		}
	}

	// Check OTEL_EXPORTER_OTLP_TRACES_ENDPOINT
	tracesEndpoint := getEnvValue(envs, "OTEL_EXPORTER_OTLP_TRACES_ENDPOINT")
	if tracesEndpoint != "" && !containsCloudWatchAgent(tracesEndpoint) {
		// If Application Signals is explicitly disabled, don't inject
		if isApplicationSignalsExplicitlyDisabled(envs) {
			return false
		}
	}

	return true
}

// shouldDisableMetrics determines if metrics should be disabled (OTEL_METRICS_EXPORTER=none)
func shouldDisableMetrics(envs []corev1.EnvVar) bool {
	// Check if OTEL_EXPORTER_OTLP_ENDPOINT is set and doesn't contain cloudwatch-agent
	otlpEndpoint := getEnvValue(envs, "OTEL_EXPORTER_OTLP_ENDPOINT")
	if otlpEndpoint != "" && !containsCloudWatchAgent(otlpEndpoint) {
		// If Application Signals is explicitly enabled, don't disable metrics
		if isApplicationSignalsExplicitlyEnabled(envs) {
			return false
		}
	}

	// Check if OTEL_EXPORTER_OTLP_METRICS_ENDPOINT is set
	metricsEndpoint := getEnvValue(envs, "OTEL_EXPORTER_OTLP_METRICS_ENDPOINT")
	if metricsEndpoint != "" {
		return false
	}

	// Default behavior is to disable metrics for Application Signals
	return true
}

// shouldDisableLogs determines if logs should be disabled (OTEL_LOGS_EXPORTER=none)
func shouldDisableLogs(envs []corev1.EnvVar) bool {
	// Check if OTEL_EXPORTER_OTLP_ENDPOINT is set and doesn't contain cloudwatch-agent
	otlpEndpoint := getEnvValue(envs, "OTEL_EXPORTER_OTLP_ENDPOINT")
	if otlpEndpoint != "" && !containsCloudWatchAgent(otlpEndpoint) {
		// If Application Signals is explicitly enabled, don't disable logs
		if isApplicationSignalsExplicitlyEnabled(envs) {
			return false
		}
	}

	// Check if OTEL_EXPORTER_OTLP_LOGS_ENDPOINT is set
	logsEndpoint := getEnvValue(envs, "OTEL_EXPORTER_OTLP_LOGS_ENDPOINT")
	if logsEndpoint != "" {
		return false
	}

	// Default behavior is to disable logs for Application Signals
	return true
}

// shouldOverrideTracesEndpoint determines if the traces endpoint should be overridden
func shouldOverrideTracesEndpoint(envs []corev1.EnvVar) bool {
	// Check if OTEL_EXPORTER_OTLP_ENDPOINT is set and doesn't contain cloudwatch-agent
	otlpEndpoint := getEnvValue(envs, "OTEL_EXPORTER_OTLP_ENDPOINT")
	if otlpEndpoint != "" && !containsCloudWatchAgent(otlpEndpoint) {
		// If Application Signals is explicitly enabled, don't override traces endpoint
		if isApplicationSignalsExplicitlyEnabled(envs) {
			return false
		}
	}

	// Check if OTEL_EXPORTER_OTLP_TRACES_ENDPOINT is already set
	tracesEndpoint := getEnvValue(envs, "OTEL_EXPORTER_OTLP_TRACES_ENDPOINT")
	if tracesEndpoint != "" {
		return false
	}

	// Default behavior is to override traces endpoint for Application Signals
	return true
}

// shouldInjectEnvVar determines whether a specific environment variable should be injected
// based on its name and the existing environment variables in the container
func shouldInjectEnvVar(envs []corev1.EnvVar, envName, envValue string) bool {
	// If the environment variable is already set, don't override it
	if getEnvValue(envs, envName) != "" {
		return false
	}

	// Apply specific validation rules based on the environment variable name
	switch envName {
	case "OTEL_METRICS_EXPORTER":
		if envValue == "none" {
			return shouldDisableMetrics(envs)
		} else if envValue == "otlp" {
			// For Python default case: only set to "otlp" if metrics should not be disabled
			return !shouldDisableMetrics(envs)
		}
	case "OTEL_LOGS_EXPORTER":
		if envValue == "none" {
			return shouldDisableLogs(envs)
		}
	case "OTEL_EXPORTER_OTLP_TRACES_ENDPOINT":
		return shouldOverrideTracesEndpoint(envs)
	case "OTEL_TRACES_EXPORTER":
		// Only set to "none" if no custom traces endpoint is configured
		return getEnvValue(envs, "OTEL_EXPORTER_OTLP_TRACES_ENDPOINT") == ""

	// For all other OTEL_ environment variables, apply general validation
	default:
		if strings.HasPrefix(envName, "OTEL_") {
			// Don't override any explicitly set OTEL_ environment variables
			return getEnvValue(envs, envName) == ""
		}
	}

	// For non-OTEL environment variables, always inject if not already set
	return true
}
