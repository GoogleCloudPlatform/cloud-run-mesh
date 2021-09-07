WIP, not used yet: using the rest API directly to fetch mesh-env and tokens.

Based on a subset of kelseyhightower/konfig.

Istio-agent has size requirements and so far has avoided a dependency on k8s api library,
which is relatively heavy and focused on controllers. 

All we really need is getting a config map with a GET request, 
and creating a token with a POST request - both using JWTs from
the default credentials source. We also don't need the full json - 
just few fields that are stable, so keeping a dependency to the 
full generated structs of all k8s APIs is overkill. 

This includes minimal code to parse kubeconfig, just enough for 
debugging. 

# Discovery 

The code is currently 'optimized' for GCP, but can be extended 
to any similar provider, if a REST 'discovery' API is provided.
We use the container API to list the clusters in the same project,
and select a cluster in the same region based on labels (falling back
to other regions if the local one is not available).
