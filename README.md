# we45 REST API Security Tester

This tool has been developed by we45's team to enhance application security testing for REST API, especially around templating and fuzzing JSON values in HTTP requests and responses. 
From a DevOps standpoint, this tool is ultimately aimed at providing an instrumentation layer for scanners like Burp, ZAP, etc to be able to test web services (specifically REST API) with a higher level of parameterization.
This is meant to be a Postman like extension on security steroids! 

## The way it works: 
- The tester creates a YAML spec for running through the REST API. The YAML spec contains details of each request and expected response. 
- The YAML spec will define the HTTP(S) requests and expected response. 
- The script will run through the spec, with probably a proxy as a MiTM run through the app
- The tester can integrate this into any CI workflow along with scanners like Burp, ZAP, etc. 

## TODOs
- JSON Templating for Fuzzing
- JSON validation for test management
- Fuzzing JSON with FuzzDB