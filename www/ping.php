Ping health check for load balancing. 
Notice this is an explicitly different target than / for two reasons:

1. Ping for load balancer should return 200. If auto-initiate config option is turned on a redirect code would be correctly sent sometimes for /, thus confusing the load balancer into thinking this is not a healthy image.

2. extensibility. In future versions/customizations may perform additional tests here before returning 200.