package main

import (
	"context"
	"fmt"
	"log"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/ec2/types"
)

func main() {
	ctx := context.Background()
	dryRun := false
	regions := []string{
		"us-east-1", // North Virginia.
		"eu-west-1", // London.
		"eu-west-2", // Ireland.
	}
	run(ctx, dryRun, regions)
}

func run(ctx context.Context, dryRun bool, regions []string) {
	for _, region := range regions {
		runInRegion(ctx, dryRun, region)
	}
}

func runInRegion(ctx context.Context, dryRun bool, region string) {
	log.Printf("running in region: %v\n", region)
	cfg, err := config.LoadDefaultConfig(ctx, config.WithRegion(region))
	if err != nil {
		log.Fatalf("unable to load SDK config: %v", err)
	}
	svc := ec2.NewFromConfig(cfg)

	var groupIDs []string
	for {
		var nextToken *string
		groups, err := svc.DescribeSecurityGroups(ctx, &ec2.DescribeSecurityGroupsInput{})
		if err != nil {
			log.Fatalf("failed to describe security groups: %v", err)
		}
		for _, sg := range groups.SecurityGroups {
			if *sg.GroupName == "default" {
				groupIDs = append(groupIDs, *sg.GroupId)
				log.Printf("found default security group in VPC %s: %s - %q\n", *sg.VpcId, *sg.GroupId, *sg.GroupName)
			}
		}
		nextToken = groups.NextToken
		if nextToken == nil {
			break
		}
	}

	var ingressRuleIDs []string
	var egressRuleIDs []string
	for _, groupID := range groupIDs {
		for {
			var nextToken *string
			rules, err := svc.DescribeSecurityGroupRules(ctx, &ec2.DescribeSecurityGroupRulesInput{
				Filters: []types.Filter{
					{
						Name:   aws.String("group-id"),
						Values: []string{groupID},
					},
				},
				NextToken: nextToken,
			})
			if err != nil {
				log.Fatalf("failed to describe security group rules: %v", err)
			}
			for _, rule := range rules.SecurityGroupRules {
				if rule.IsEgress != nil && *rule.IsEgress {
					egressRuleIDs = append(egressRuleIDs, *rule.SecurityGroupRuleId)
					if dryRun {
						log.Printf("dryRun: would have deleted egress rule %s from security group %s\n", *rule.SecurityGroupRuleId, groupID)
					} else {
						log.Printf("deleting egress rule %s from security group %s\n", *rule.SecurityGroupRuleId, groupID)
						_, err = svc.RevokeSecurityGroupEgress(ctx, &ec2.RevokeSecurityGroupEgressInput{
							GroupId:              &groupID,
							SecurityGroupRuleIds: []string{*rule.SecurityGroupRuleId},
						})
						if err != nil {
							log.Fatalf("error deleting rule: %v\n", err)
						}
					}
				} else {
					ingressRuleIDs = append(ingressRuleIDs, *rule.SecurityGroupRuleId)
					if dryRun {
						log.Printf("dryRun: would have deleted ingress rule %s from security group %s\n", *rule.SecurityGroupRuleId, groupID)
					} else {
						log.Printf("deleting ingress rule %s from security group %s\n", *rule.SecurityGroupRuleId, groupID)
						_, err = svc.RevokeSecurityGroupIngress(ctx, &ec2.RevokeSecurityGroupIngressInput{
							GroupId:              &groupID,
							SecurityGroupRuleIds: []string{*rule.SecurityGroupRuleId},
						})
						if err != nil {
							log.Fatalf("error deleting rule: %v\n", err)
						}
					}
				}
			}
			nextToken = rules.NextToken
			if nextToken == nil {
				break
			}
		}
	}
	fmt.Printf("Revoked %d ingress and %d egress rules in region %s...\n", len(ingressRuleIDs), len(egressRuleIDs), region)
}
