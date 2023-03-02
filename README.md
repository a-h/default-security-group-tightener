# Default Security Group Tightener

> Delete ingress and egress rules associated with the default VPC in your AWS accounts

```shell
export DRYRUN=true
export REGIONS="us-east-1,eu-west-1,eu-west-2"
go run main.go
```
