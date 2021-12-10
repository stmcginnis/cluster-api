/*
Copyright 2021 The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package container

import (
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"strings"

	"github.com/pkg/errors"
)

type podmanRuntime struct {
	podman string
}

// NewPodmanClient gets a client for interacting with a Podman container runtime.
func NewPodmanClient() (Runtime, error) {
	// Minimal check to make sure the podman executable can be found.
	path, err := exec.LookPath("podman")
	if err != nil {
		return nil, err
	}

	return &podmanRuntime{
		podman: path,
	}, nil
}

// execCommand will execute a command and return the combined stdout and stderr output
// along with any error.
func (p *podmanRuntime) execCommand(ctx context.Context, args ...string) (lines []string, err error) {
	cmd := exec.CommandContext(ctx, p.podman, args...) //nolint:gosec
	buff, err := cmd.CombinedOutput()
	lines = strings.Split(string(buff), "\n")
	return lines, err
}

// SaveContainerImage saves a container image to the file specified by dest.
func (p *podmanRuntime) SaveContainerImage(ctx context.Context, image, dest string) error {
	// https://docs.podman.io/en/latest/markdown/podman-save.1.html
	_, err := p.execCommand(ctx, "save", "--quiet", "--format=docker-archive", "-o", dest, image)
	return err
}

// PullContainerImageIfNotExists triggers the Podman engine to pull an image, but only if it doesn't
// already exist. This is important when we're using locally built images in CI which
// do not exist remotely.
func (p *podmanRuntime) PullContainerImageIfNotExists(ctx context.Context, image string) error {
	// https://docs.podman.io/en/latest/markdown/podman-image-exists.1.html
	// https://docs.podman.io/en/latest/markdown/podman-pull.1.html
	_, err := p.execCommand(ctx, "image", "exists", image)
	if err != nil {
		// Image doesn't exist, so fetch it
		_, err = p.execCommand(ctx, "pull", image)
	}
	return err
}

// GetHostPort looks up the host port bound for the port and protocol (e.g. "6443/tcp").
func (p *podmanRuntime) GetHostPort(ctx context.Context, containerName, portAndProtocol string) (string, error) {
	// https://docs.podman.io/en/latest/markdown/podman-container-inspect.1.html
	portFormat := `{{index (index (index .NetworkSettings.Ports "` + portAndProtocol + `") 0) "HostPort"}}`
	output, err := p.execCommand(ctx, "container", "inspect", containerName, "--format", portFormat)
	if err != nil {
		return "", err
	}

	if len(output) == 0 {
		return "", fmt.Errorf("no host port found for %q", containerName)
	}

	return strings.TrimSpace(output[0]), nil
}

// ExecContainer executes a command in a running container and writes any output to the provided writer.
func (p *podmanRuntime) ExecContainer(ctx context.Context, containerName string, config *ExecContainerInput, command string, cmdArgs ...string) error {
	// https://docs.podman.io/en/latest/markdown/podman-exec.1.html
	args := []string{
		"exec",
		// run with privileges so we can remount etc..
		// this might not make sense in the most general sense, but it is
		// important to many kind commands
		"--privileged",
	}
	if config.InputBuffer != nil {
		args = append(args,
			"-i", // interactive so we can supply input
		)
	}
	// set env
	for _, env := range config.EnvironmentVars {
		args = append(args, "-e", env)
	}
	// specify the container and command, after this everything will be
	// args the the command in the container rather than to podman
	args = append(
		args,
		containerName, // ... against the container
		command,       // with the command specified
	)
	args = append(
		args,
		// finally, with the caller args
		cmdArgs...,
	)
	cmd := exec.CommandContext(ctx, p.podman, args...) //nolint:gosec
	if config.InputBuffer != nil {
		cmd.Stdin = config.InputBuffer
	}
	if config.ErrorBuffer != nil {
		cmd.Stderr = config.ErrorBuffer
	}
	if config.OutputBuffer != nil {
		cmd.Stdout = config.OutputBuffer
	}
	return errors.WithStack(cmd.Run())
}

// ListContainers returns a list of all containers.
func (p *podmanRuntime) ListContainers(ctx context.Context, filters FilterBuilder) ([]Container, error) {
	// https://docs.podman.io/en/latest/markdown/podman-ps.1.html
	args := []string{
		"ps",
		"-q",         // quiet output for parsing
		"-a",         // show stopped nodes
		"--no-trunc", // don't truncate
		// format to include friendly name and
		"--format", "{{.Names}}\t{{.Status}}\t{{.Image}}",
	}

	// Construct our filtering options
	for key, values := range filters {
		for subkey, subvalues := range values {
			for _, v := range subvalues {
				if v == "" {
					args = append(args, "--filter", fmt.Sprintf("%s=%s", key, subkey))
				} else {
					args = append(args, "--filter", fmt.Sprintf("%s=%s=%s", key, subkey, v))
				}
			}
		}
	}

	lines, err := p.execCommand(ctx, args...)
	if err != nil {
		return nil, errors.Wrap(err, "failed to list containers")
	}

	containers := []Container{}
	for _, line := range lines {
		parts := strings.Split(line, "\t")
		if len(parts) != 3 {
			return nil, errors.Errorf("invalid output when listing nodes: %s", line)
		}
		names := strings.Split(parts[0], ",")
		status := parts[1]
		image := parts[2]
		container := Container{
			Name:   names[0],
			Image:  image,
			Status: status,
		}
		containers = append(containers, container)
	}

	return containers, nil
}

// DeleteContainer will remove a container, forcing removal if still running.
func (p *podmanRuntime) DeleteContainer(ctx context.Context, containerName string) error {
	// https://docs.podman.io/en/latest/markdown/podman-rm.1.html
	_, err := p.execCommand(ctx, "rm",
		// force the container to be deleted now
		"-f",
		// delete volumes
		"-v",
		containerName)
	return err
}

// KillContainer will kill a running container with the specified signal.
func (p *podmanRuntime) KillContainer(ctx context.Context, containerName, signal string) error {
	// https://docs.podman.io/en/latest/markdown/podman-kill.1.html
	_, err := p.execCommand(ctx, "kill",
		"-s", signal,
		containerName)
	return err
}

// GetContainerIPs inspects a container to get its IPv4 and IPv6 IP addresses.
// Will not error if there is no IP address assigned. Calling code will need to
// determine whether that is an issue or not.
func (p *podmanRuntime) GetContainerIPs(ctx context.Context, containerName string) (string, string, error) {
	// https://docs.podman.io/en/latest/markdown/podman-container-inspect.1.html
	lines, err := p.execCommand(ctx, "inspect",
		"-f", "{{range .NetworkSettings.Networks}}{{.IPAddress}},{{.GlobalIPv6Address}}{{end}}",
		containerName)
	if err != nil {
		return "", "", errors.Wrap(err, "failed to get container details")
	}
	if len(lines) != 1 {
		return "", "", errors.Errorf("container IP info should only be one line, got %d lines", len(lines))
	}
	ips := strings.Split(lines[0], ",")
	if len(ips) != 2 {
		return "", "", errors.Errorf("container addresses should have 2 values, got %d values", len(ips))
	}
	return ips[0], ips[1], nil
}

// ContainerDebugInfo gets the container metadata and logs from the runtime (podman inspect, podman logs).
func (p *podmanRuntime) ContainerDebugInfo(ctx context.Context, containerName string, w io.Writer) error {
	// https://docs.podman.io/en/latest/markdown/podman-container-inspect.1.html
	lines, err := p.execCommand(ctx, "inspect", containerName)
	if err != nil {
		return errors.Wrap(err, "failed to inspect container")
	}

	fmt.Fprintln(w, "Inspected the container:")
	fmt.Fprintf(w, "%s\n", strings.Join(lines, "\n"))

	// https://docs.podman.io/en/latest/markdown/podman-logs.1.html
	fmt.Fprintln(w, "Got logs from the container:")
	cmd := exec.CommandContext(ctx, p.podman, "logs", containerName) //nolint:gosec
	cmd.Stderr = w
	cmd.Stdout = w

	return errors.WithStack(cmd.Run())
}

// RunContainer will run a podman container with the given settings and arguments, returning any errors.
func (p *podmanRuntime) RunContainer(ctx context.Context, runConfig *RunContainerInput, output io.Writer) error {
	// https://docs.podman.io/en/latest/markdown/podman-run.1.html
	runArgs := []string{
		"--detach", // run the container detached
		"--tty",    // allocate a tty for entrypoint logs
		// running containers in a container requires privileged
		// NOTE: we could try to replicate this with --cap-add, and use less
		// privileges, but this flag also changes some mounts that are necessary
		// including some ones docker would otherwise do by default.
		// for now this is what we want. in the future we may revisit this.
		"--privileged",
		"--security-opt", "seccomp=unconfined", // also ignore seccomp
		// runtime temporary storage
		"--tmpfs", "/tmp", // various things depend on working /tmp
		"--tmpfs", "/run", // systemd wants a writable /run
		// runtime persistent storage
		// this ensures that E.G. pods, logs etc. are not on the container
		// filesystem, which is not only better for performance, but allows
		// running kind in kind for "party tricks"
		// (please don't depend on doing this though!)
		"--volume", "/var",
		// some k8s things want to read /lib/modules
		"--volume", "/lib/modules:/lib/modules:ro",
		"--hostname", runConfig.Name, // make hostname match container name
		"--network", runConfig.Network,
		"--name", runConfig.Name, // ... and set the container name
	}

	for label, value := range runConfig.Labels {
		if value != "" {
			runArgs = append(runArgs, "--label", label, value)
		} else {
			runArgs = append(runArgs, "--label", label)
		}
	}

	// pass proxy environment variables to be used by node's docker daemon
	proxyDetails, err := p.getProxyDetails(ctx, runConfig.Network)
	if err != nil || proxyDetails == nil {
		return errors.Wrap(err, "proxy setup error")
	}
	for key, val := range proxyDetails.Envs {
		runArgs = append(runArgs, "-e", fmt.Sprintf("%s=%s", key, val))
	}

	// adds node specific args
	runArgs = append(runArgs, runConfig.CommandArgs...)

	if p.usernsRemap(ctx) {
		// We need this argument in order to make this command work
		// in systems that have userns-remap enabled on the docker daemon
		runArgs = append(runArgs, "--userns=host")
	}

	return p.run(
		ctx,
		runConfig.Image,
		withRunArgs(runArgs...),
		withMounts(runConfig.Mounts),
		withPortMappings(runConfig.PortMappings),
	)
}

func (p *podmanRuntime) run(ctx context.Context, image string, opts ...RunOpt) error {
	o := &runOpts{}
	for _, opt := range opts {
		o = opt(o)
	}
	// convert mounts to container run args
	runArgs := o.RunArgs
	for _, mount := range o.Mounts {
		runArgs = append(runArgs, generateMountBindings(mount)...)
	}
	for _, portMapping := range o.PortMappings {
		runArgs = append(runArgs, generatePortMappings(portMapping)...)
	}
	// construct the actual docker run argv
	args := []string{"run"}
	args = append(args, runArgs...)
	args = append(args, image)
	args = append(args, o.ContainerArgs...)
	output, err := p.execCommand(ctx, args...)
	if err != nil {
		// log error output if there was any
		for _, line := range output {
			fmt.Println(line)
		}
		return err
	}
	return nil
}

// usernsRemap checks if userns-remap is enabled in podman.
func (p *podmanRuntime) usernsRemap(ctx context.Context) bool {
	output, err := p.execCommand(ctx, "info")
	if err != nil {
		return false
	}

	for _, secOpt := range output {
		if strings.Contains(secOpt, "name=userns") {
			return true
		}
	}
	return false
}

// RunOpt is an option for run.
type RunOpt func(*runOpts) *runOpts

// actual options struct.
type runOpts struct {
	RunArgs       []string
	ContainerArgs []string
	Mounts        []Mount
	PortMappings  []PortMapping
}

// withRunArgs sets the args for docker run
// as in the args portion of `podman run args... image containerArgs...`.
func withRunArgs(args ...string) RunOpt {
	return func(r *runOpts) *runOpts {
		r.RunArgs = args
		return r
	}
}

// withMounts sets the container mounts.
func withMounts(mounts []Mount) RunOpt {
	return func(r *runOpts) *runOpts {
		r.Mounts = mounts
		return r
	}
}

// withPortMappings sets the container port mappings to the host.
func withPortMappings(portMappings []PortMapping) RunOpt {
	return func(r *runOpts) *runOpts {
		r.PortMappings = portMappings
		return r
	}
}

func generateMountBindings(mounts ...Mount) []string {
	result := make([]string, 0, len(mounts))
	for _, m := range mounts {
		bind := fmt.Sprintf("%s:%s", m.Source, m.Target)
		var attrs []string
		if m.ReadOnly {
			attrs = append(attrs, "ro")
		}

		if len(attrs) > 0 {
			bind = fmt.Sprintf("%s:%s", bind, strings.Join(attrs, ","))
		}
		// our specific modification is the following line: make this a docker flag
		bind = fmt.Sprintf("--volume=%s", bind)
		result = append(result, bind)
	}
	return result
}

func generatePortMappings(portMappings ...PortMapping) []string {
	result := make([]string, 0, len(portMappings))
	for _, pm := range portMappings {
		var hostPortBinding string
		if pm.ListenAddress != "" {
			hostPortBinding = net.JoinHostPort(pm.ListenAddress, fmt.Sprintf("%d", pm.HostPort))
		} else {
			hostPortBinding = fmt.Sprintf("%d", pm.HostPort)
		}
		publish := fmt.Sprintf("--publish=%s:%d/%s", hostPortBinding, pm.ContainerPort, strings.ToUpper(pm.Protocol))
		result = append(result, publish)
	}
	return result
}

// getProxyDetails returns a struct with the host environment proxy settings
// that should be passed to the nodes.
func (p *podmanRuntime) getProxyDetails(ctx context.Context, network string) (*proxyDetails, error) {
	var val string
	details := proxyDetails{Envs: make(map[string]string)}
	proxyEnvs := []string{httpProxy, httpsProxy, noProxy}
	proxySupport := false

	for _, name := range proxyEnvs {
		val = os.Getenv(name)
		if val == "" {
			val = os.Getenv(strings.ToLower(name))
		}
		if val == "" {
			continue
		}
		proxySupport = true
		details.Envs[name] = val
		details.Envs[strings.ToLower(name)] = val
	}

	// Specifically add the podman network subnets to NO_PROXY if we are using proxies
	if proxySupport {
		subnets, err := p.getSubnets(ctx, network)
		if err != nil {
			return &details, err
		}
		noProxyList := strings.Join(append(subnets, details.Envs[noProxy]), ",")
		details.Envs[noProxy] = noProxyList
		details.Envs[strings.ToLower(noProxy)] = noProxyList
	}

	return &details, nil
}

// getSubnets returns a slice of subnets for a specified network.
func (p *podmanRuntime) getSubnets(ctx context.Context, networkName string) ([]string, error) {
	format := `{{range (index (index . "IPAM") "Config")}}{{index . "Subnet"}} {{end}}`
	lines, err := p.execCommand(ctx, "network", "inspect", "-f", format, networkName)
	if err != nil {
		return nil, err
	}
	subnets := []string{}
	for _, network := range lines {
		subnets = append(subnets, strings.Trim(network, " "))
	}

	return subnets, nil
}
