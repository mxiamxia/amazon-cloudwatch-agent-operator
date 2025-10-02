// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package instrumentation

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	"k8s.io/utils/strings/slices"
	"sigs.k8s.io/controller-runtime/pkg/client"

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

// setInitContainerSecurityContext returns a SecurityContext for init containers
// based on the pod's existing security context. It intelligently determines whether
// a SecurityContext is needed and what values to use.
//
// Logic:
// - If pod has runAsNonRoot=true but no runAsUser set: Set runAsUser=1000 to satisfy the constraint
// - If pod already has runAsUser set: Return nil (init container will inherit from pod)
// - If neither is set: Return nil (let image default apply)
//
// This ensures init containers respect the pod's security policy without forcing
// unnecessary constraints.
func setInitContainerSecurityContext(pod corev1.Pod) *corev1.SecurityContext {
	// Check pod-level SecurityContext
	if pod.Spec.SecurityContext == nil {
		// No pod-level SecurityContext - let image defaults apply
		return nil
	}

	podSC := pod.Spec.SecurityContext

	// If pod already has runAsUser set at pod level, init container will inherit it
	if podSC.RunAsUser != nil {
		// Pod-level runAsUser exists - init will inherit, no need to set explicitly
		return nil
	}

	// If pod has runAsNonRoot=true but no runAsUser, we need to provide a non-root UID
	if podSC.RunAsNonRoot != nil && *podSC.RunAsNonRoot {
		// Pod requires non-root but doesn't specify which UID
		// Set a safe default non-root UID (1000)
		runAsUser := int64(1000)
		runAsNonRoot := true
		return &corev1.SecurityContext{
			RunAsUser:    &runAsUser,
			RunAsNonRoot: &runAsNonRoot,
		}
	}

	// No constraints - let image default apply
	return nil
}

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

// resolveEnvFrom fetches ConfigMap/Secret data referenced by envFrom and returns as EnvVar slice
// Uses caches to avoid redundant API calls when multiple containers reference the same ConfigMap/Secret
func resolveEnvFrom(ctx context.Context, k8sClient client.Client, envFromSources []corev1.EnvFromSource, namespace string, logger logr.Logger, configMapCache map[string]*corev1.ConfigMap, secretCache map[string]*corev1.Secret) []corev1.EnvVar {
	var resolvedEnvs []corev1.EnvVar

	for _, envFromSource := range envFromSources {
		if envFromSource.ConfigMapRef != nil {
			cmName := envFromSource.ConfigMapRef.Name
			var configMap *corev1.ConfigMap

			// Check cache first
			if cached, exists := configMapCache[cmName]; exists {
				configMap = cached
				logger.V(1).Info("using cached ConfigMap from envFrom",
					"configMap", cmName,
					"namespace", namespace)
			} else {
				// Fetch ConfigMap
				configMap = &corev1.ConfigMap{}
				err := k8sClient.Get(ctx, client.ObjectKey{
					Name:      cmName,
					Namespace: namespace,
				}, configMap)

				if err != nil {
					logger.Error(err, "failed to fetch ConfigMap for envFrom",
						"configMap", cmName,
						"namespace", namespace)
					continue
				}

				// Store in cache
				configMapCache[cmName] = configMap
				logger.V(1).Info("fetched and cached ConfigMap from envFrom",
					"configMap", cmName,
					"envCount", len(configMap.Data))
			}

			// Convert ConfigMap data to EnvVar slice
			for key, value := range configMap.Data {
				resolvedEnvs = append(resolvedEnvs, corev1.EnvVar{
					Name:  key,
					Value: value,
				})
			}
		}

		if envFromSource.SecretRef != nil {
			secretName := envFromSource.SecretRef.Name
			var secret *corev1.Secret

			// Check cache first
			if cached, exists := secretCache[secretName]; exists {
				secret = cached
				logger.V(1).Info("using cached Secret from envFrom",
					"secret", secretName,
					"namespace", namespace)
			} else {
				// Fetch Secret
				secret = &corev1.Secret{}
				err := k8sClient.Get(ctx, client.ObjectKey{
					Name:      secretName,
					Namespace: namespace,
				}, secret)

				if err != nil {
					logger.Error(err, "failed to fetch Secret for envFrom",
						"secret", secretName,
						"namespace", namespace)
					continue
				}

				// Store in cache
				secretCache[secretName] = secret
				logger.V(1).Info("fetched and cached Secret from envFrom",
					"secret", secretName,
					"envCount", len(secret.Data))
			}

			// Convert Secret data to EnvVar slice
			for key, value := range secret.Data {
				resolvedEnvs = append(resolvedEnvs, corev1.EnvVar{
					Name:  key,
					Value: string(value),
				})
			}
		}
	}

	return resolvedEnvs
}

// getAllEnvVars combines direct env vars and envFrom-resolved vars
// Always processes both direct env and envFrom for consistency, using caches to optimize performance
func getAllEnvVars(ctx context.Context, k8sClient client.Client, container *corev1.Container, namespace string, logger logr.Logger, configMapCache map[string]*corev1.ConfigMap, secretCache map[string]*corev1.Secret) []corev1.EnvVar {
	allEnvs := make([]corev1.EnvVar, len(container.Env))
	copy(allEnvs, container.Env)

	// Always resolve envFrom sources for consistency (even if empty)
	if len(container.EnvFrom) > 0 {
		resolvedEnvs := resolveEnvFrom(ctx, k8sClient, container.EnvFrom, namespace, logger, configMapCache, secretCache)

		// envFrom has lower precedence than direct env
		// Build map of existing env var names for O(1) lookup
		envMap := make(map[string]bool, len(allEnvs))
		for _, env := range allEnvs {
			envMap[env.Name] = true
		}

		// Add resolved envs only if not already defined in direct env
		for _, resolvedEnv := range resolvedEnvs {
			if !envMap[resolvedEnv.Name] {
				allEnvs = append(allEnvs, resolvedEnv)
			}
		}

		logger.V(1).Info("resolved all environment variables",
			"directEnvCount", len(container.Env),
			"envFromCount", len(resolvedEnvs),
			"totalEnvCount", len(allEnvs))
	}

	return allEnvs
}

// shouldInjectADOTSDK determines if the ADOT SDK should be injected based on existing environment variables
// and the pod/container security context
func shouldInjectADOTSDK(envs []corev1.EnvVar, pod corev1.Pod, container *corev1.Container) bool {
	// Check Pod-level SecurityContext for runAsNonRoot without runAsUser
	if pod.Spec.SecurityContext != nil {
		podSC := pod.Spec.SecurityContext
		if podSC.RunAsNonRoot != nil && *podSC.RunAsNonRoot && podSC.RunAsUser == nil {
			// Pod requires non-root but doesn't specify UID - skip injection to avoid init container issues
			return false
		}
	}

	// Check Container-level SecurityContext for runAsNonRoot without runAsUser
	if container.SecurityContext != nil {
		containerSC := container.SecurityContext
		if containerSC.RunAsNonRoot != nil && *containerSC.RunAsNonRoot && containerSC.RunAsUser == nil {
			// Container requires non-root but doesn't specify UID - skip injection to avoid init container issues
			return false
		}
	}

	// Check OTEL_EXPORTER_OTLP_ENDPOINT
	otlpEndpoint := getEnvValue(envs, "OTEL_EXPORTER_OTLP_ENDPOINT")
	if otlpEndpoint != "" && !containsCloudWatchAgent(otlpEndpoint) {
		// If user has a custom OTLP endpoint, only inject if Application Signals is explicitly enabled
		return isApplicationSignalsExplicitlyEnabled(envs)
	}

	// Check OTEL_EXPORTER_OTLP_TRACES_ENDPOINT
	tracesEndpoint := getEnvValue(envs, "OTEL_EXPORTER_OTLP_TRACES_ENDPOINT")
	if tracesEndpoint != "" && !containsCloudWatchAgent(tracesEndpoint) {
		// If user has a custom traces endpoint, only inject if Application Signals is explicitly enabled
		return isApplicationSignalsExplicitlyEnabled(envs)
	}

	// Default: inject if no custom endpoints are configured and no problematic security context
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
		}
	case "OTEL_LOGS_EXPORTER":
		if envValue == "none" {
			return shouldDisableLogs(envs)
		}
	case "OTEL_EXPORTER_OTLP_TRACES_ENDPOINT":
		return shouldOverrideTracesEndpoint(envs)
	case "OTEL_TRACES_SAMPLER":
		return shouldOverrideTracesEndpoint(envs)
	case "OTEL_TRACES_SAMPLER_ARG":
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
