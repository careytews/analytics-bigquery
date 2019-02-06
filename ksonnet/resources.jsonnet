
//
// Definition for BigQuery worker
//

// Import KSonnet library.
local k = import "ksonnet.beta.2/k.libsonnet";

// Short-cuts to various objects in the KSonnet library.
local depl = k.extensions.v1beta1.deployment;
local container = depl.mixin.spec.template.spec.containersType;
local mount = container.volumeMountsType;
local volume = depl.mixin.spec.template.spec.volumesType;
local resources = container.resourcesType;
local env = container.envType;
local secretDisk = volume.mixin.secret;
local base = import "base.jsonnet";
local annotations = depl.mixin.spec.template.metadata.annotations;

local bigquery(input, output) =
    local worker(config) = {

        local version = import "version.jsonnet",

        name: "analytics-bigquery",
        images: ["gcr.io/trust-networks/analytics-bigquery:" + version],

        input: input,
        output: output,

        // Volumes - single volume containing the key secret
        volumeMounts:: [
            mount.new("keys", "/key") + mount.readOnly(true)
        ],

        // Environment variables
        envs:: [

            // Hostname of Cherami
            env.new("CHERAMI_FRONTEND_HOST", "cherami"),
            
            // Pathname of key file.
            env.new("KEY", "/key/private.json"),
            
            // Bigquery table settings
            env.new("BIGQUERY_PROJECT", config.project),
            env.new("BIGQUERY_DATASET", "cyberprobe"),
            env.new("RAW_TABLE", "cyberprobe")
            
        ],

        // Container definition.
        containers:: [
            container.new(self.name, self.images[0]) +
                container.volumeMounts(self.volumeMounts) +
                container.env(self.envs) +
                container.args(["/queue/" + input] +
                               std.map(function(x) "output:/queue/" + x,
                                       output)) +
                container.mixin.resources.limits({
                    memory: "128M", cpu: "1.0"
                }) +
                container.mixin.resources.requests({
                    memory: "128M", cpu: "0.2"
                })
        ],

        volumes:: [
            volume.name("keys") +
                secretDisk.secretName("analytics-bigquery-keys")
        ],

        // Deployment definition.  replicas is number of container replicas,
        // inp is the input queue name, out is an array of output queue names.
        deployments:: [
            depl.new("analytics-bigquery",
                     config.workers.replicas.bigquery,
                     self.containers,
                     {app: "analytics-bigquery",
                      component: "analytics"}) +
                depl.mixin.spec.template.spec.volumes(self.volumes) +
		annotations({"prometheus.io/scrape": "true", 
			     "prometheus.io/port": "8080"})
        ],
	
        resources: self.deployments
    };
    worker;

bigquery


