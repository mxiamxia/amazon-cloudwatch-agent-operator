// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package instrumentation

import (
	corev1 "k8s.io/api/core/v1"
	"sigs.k8s.io/controller-runtime/pkg/log"

	"github.com/aws/amazon-cloudwatch-agent-operator/apis/v1alpha1"
)

const (
	envJavaToolsOptions       = "JAVA_TOOL_OPTIONS"
	javaJVMArgument           = " -javaagent:/otel-auto-instrumentation-java/javaagent.jar"
	javaInitContainerName     = initContainerName + "-java"
	javaVolumeName            = volumeName + "-java"
	javaInstrMountPath        = "/otel-auto-instrumentation-java"
	javaInstrMountPathWindows = "\\otel-auto-instrumentation-java"
)

var (
	javaCommandLinux   = []string{"cp", "/javaagent.jar", javaInstrMountPath + "/javaagent.jar"}
	javaCommandWindows = []string{"CMD", "/c", "copy", "javaagent.jar", javaInstrMountPathWindows}
)

func injectJavaagent(javaSpec v1alpha1.Java, pod corev1.Pod, index int) (corev1.Pod, error) {
	logger := log.Log.WithName("javaagent-injection")
	logger.Info("injectJavaagent triggered",
		"pod", pod.Name,
		"namespace", pod.Namespace,
		"container", pod.Spec.Containers[index].Name,
		"containerIndex", index)

	// caller checks if there is at least one container.
	container := &pod.Spec.Containers[index]

	// Add test environment variable to indicate new operator auto-monitor functionality
	container.Env = append(container.Env, corev1.EnvVar{
		Name:  "NEW_OPERATOR",
		Value: "AUTOMONITOR",
	})
	logger.Info("added test environment variable NEW_OPERATOR=AUTOMONITOR",
		"pod", pod.Name,
		"container", pod.Spec.Containers[index].Name)

	err := validateContainerEnv(container.Env, envJavaToolsOptions)
	if err != nil {
		logger.Error(err, "container environment validation failed")
		return pod, err
	}

	// Check if ADOT SDK should be injected based on existing environment variables
	if !shouldInjectADOTSDK(container.Env) {
		logger.Info("ADOT SDK injection skipped due to existing environment variables",
			"pod", pod.Name,
			"container", pod.Spec.Containers[index].Name)
		return pod, nil
	}

	logger.Info("proceeding with Java agent injection",
		"pod", pod.Name,
		"container", pod.Spec.Containers[index].Name)

	// inject Java instrumentation spec env vars with validation.
	for _, env := range javaSpec.Env {
		logger.Info("processing Java spec environment variable",
			"name", env.Name,
			"value", env.Value,
			"pod", pod.Name,
			"container", pod.Spec.Containers[index].Name)
		if shouldInjectEnvVar(container.Env, env.Name, env.Value) {
			container.Env = append(container.Env, env)
			logger.Info("injected Java spec environment variable",
				"name", env.Name,
				"value", env.Value)
		} else {
			logger.Info("skipped Java spec environment variable injection",
				"name", env.Name,
				"value", env.Value,
				"reason", "validation failed or already exists")
		}
	}

	idx := getIndexOfEnv(container.Env, envJavaToolsOptions)
	if idx == -1 {
		container.Env = append(container.Env, corev1.EnvVar{
			Name:  envJavaToolsOptions,
			Value: javaJVMArgument,
		})
	} else {
		container.Env[idx].Value = container.Env[idx].Value + javaJVMArgument
	}

	container.VolumeMounts = append(container.VolumeMounts, corev1.VolumeMount{
		Name:      javaVolumeName,
		MountPath: javaInstrMountPath,
	})

	// We just inject Volumes and init containers for the first processed container.
	if isInitContainerMissing(pod, javaInitContainerName) {
		pod.Spec.Volumes = append(pod.Spec.Volumes, corev1.Volume{
			Name: javaVolumeName,
			VolumeSource: corev1.VolumeSource{
				EmptyDir: &corev1.EmptyDirVolumeSource{
					SizeLimit: volumeSize(javaSpec.VolumeSizeLimit),
				},
			}})

		command := javaCommandLinux
		if isWindowsPod(pod) {
			command = javaCommandWindows
		}

		pod.Spec.InitContainers = append(pod.Spec.InitContainers, corev1.Container{
			Name:      javaInitContainerName,
			Image:     javaSpec.Image,
			Command:   command,
			Resources: javaSpec.Resources,
			VolumeMounts: []corev1.VolumeMount{{
				Name:      javaVolumeName,
				MountPath: javaInstrMountPath,
			}},
		})
	}

	logger.Info("Java agent injection completed successfully",
		"pod", pod.Name,
		"container", pod.Spec.Containers[index].Name,
		"initContainerAdded", !isInitContainerMissing(pod, javaInitContainerName))

	return pod, err
}
