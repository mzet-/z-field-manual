
## Testing infrastructure

### EC2 node running

```
# creating new instance:
attack-fleet ec2new us-east-1

# show instance status and IP:
attack-fleet ec2show us-east-1
attack-fleet ec2ops start us-east-1 <id>
sshaws <IP>
```

### EC2 node decommission

```
attack-fleet ec2kill us-east-1 <id>
```

### Setting DNS record

    attack-fleet dnsset domain.com abc.domain.com <IP> A

### Elastic IP confuguration

```
Elastic IP setup:
aws --region us-east-1 --profile <profile> ec2 allocate-address --domain vpc
aws --region us-east-1 --profile <profile> ec2 describe-addresses
aws --region us-east-1 --profile <profile> ec2 associate-address --instance-id <instance-ID> --allocation-id <alloc-ID> 

Elastic IP teardown:
disassociate-address (https://docs.aws.amazon.com/cli/latest/reference/ec2/disassociate-address.html)
aws --region us-east-1 --profile <profile> ec2 disassociate-address --association-id <assoc-ID>
release-address (https://docs.aws.amazon.com/cli/latest/reference/ec2/release-address.html)
aws --region us-east-1 --profile <profile> ec2 release-address --allocation-id <alloc-ID>
```
