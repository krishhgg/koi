import { z } from 'zod';

// The fields koid reads from Docker's JSON output. Parsing keeps only these,
// so a Docker that prints one of them in another shape fails loudly instead
// of reading as "not running" or "not internal".

// One network, from `docker network inspect --format '{{json .}}'`, as the
// preview network checks read it.
export const DockerNetworkSchema = z.object({
	Driver: z.string(),
	Internal: z.boolean(),
	Options: z.record(z.string(), z.string()).nullish(),
});

export type DockerNetwork = z.infer<typeof DockerNetworkSchema>;

// One network, from the same command, with everything networks() reads:
// the options, the labels, the subnets and the attached containers. Every
// value arrives as JSON, so a label holding a tab or a newline cannot pose
// as another field or another network.
export const DockerNetworkInspectSchema = z.object({
	Id: z.string(),
	Name: z.string(),
	Driver: z.string(),
	Internal: z.boolean(),
	EnableIPv6: z.boolean(),
	Options: z.record(z.string(), z.string()).nullish(),
	Labels: z.record(z.string(), z.string()).nullish(),
	IPAM: z
		.object({ Config: z.array(z.object({ Subnet: z.string().optional() })).nullish() })
		.nullish(),
	Containers: z.record(z.string(), z.object({ Name: z.string() })).nullish(),
});

export type DockerNetworkInspect = z.infer<typeof DockerNetworkInspectSchema>;

// One container's name and labels, from `docker container inspect` with a
// format that prints just those two fields as JSON. The name arrives with
// Docker's leading slash.
export const DockerContainerLabelsSchema = z.object({
	Name: z.string(),
	Labels: z.record(z.string(), z.string()).nullish(),
});

export type DockerContainerLabels = z.infer<typeof DockerContainerLabelsSchema>;

// One container, from `docker container inspect` with the daemon's
// STATE_FORMAT, which prints just these fields. Networks is null for a
// container on no network, and IPAddress is empty while it is stopped.
export const DockerContainerStateSchema = z.object({
	State: z.object({ Running: z.boolean() }),
	NetworkSettings: z.object({
		Networks: z.record(z.string(), z.object({ IPAddress: z.string().optional() })).nullish(),
	}),
});

export type DockerContainerState = z.infer<typeof DockerContainerStateSchema>;

// A container's attachments, from `docker container inspect --format
// '{{json .NetworkSettings.Networks}}'`, by network name. IPAddress and
// MacAddress are empty until the container starts; IPAMConfig holds the
// address a created container was given with --ip.
export const DockerEndpointsSchema = z
	.record(
		z.string(),
		z.object({
			IPAddress: z.string().optional(),
			MacAddress: z.string().optional(),
			EndpointID: z.string().optional(),
			IPAMConfig: z.object({ IPv4Address: z.string().optional() }).nullish(),
		}),
	)
	.nullable();

export type DockerEndpoints = z.infer<typeof DockerEndpointsSchema>;

// A container's mounts, from `docker container inspect --format '{{json
// .Mounts}}'`. A volume an image declares appears here as soon as the
// container is created; a --tmpfs does not. A volume mount carries the
// volume's name, and RW says whether the container may write to it.
export const DockerMountsSchema = z
	.array(
		z.object({
			Type: z.string(),
			Destination: z.string(),
			Name: z.string().optional(),
			RW: z.boolean().optional(),
		}),
	)
	.nullable();

export type DockerMounts = z.infer<typeof DockerMountsSchema>;

// An image's environment, from `docker image inspect` with a format that
// prints `{{json .Config.Env}}`: KEY=value strings, or null when the image
// declares none.
export const DockerImageEnvSchema = z.array(z.string()).nullable();

export type DockerImageEnv = z.infer<typeof DockerImageEnvSchema>;

// What a container was created with, from `docker container inspect
// --format '{{json .HostConfig}}'`: the fields the Docker tests read back
// to check the flags koid passes for a verification helper (the daemon's
// helperArgs). CapDrop, SecurityOpt and Tmpfs are null on a container
// created without them.
export const DockerHostConfigSchema = z.object({
	ReadonlyRootfs: z.boolean(),
	CapDrop: z.array(z.string()).nullable(),
	SecurityOpt: z.array(z.string()).nullable(),
	LogConfig: z.object({ Type: z.string(), Config: z.record(z.string(), z.string()).nullable() }),
	Tmpfs: z.record(z.string(), z.string()).nullish(),
	RestartPolicy: z.object({ Name: z.string(), MaximumRetryCount: z.number() }),
	NetworkMode: z.string(),
});

export type DockerHostConfig = z.infer<typeof DockerHostConfigSchema>;
