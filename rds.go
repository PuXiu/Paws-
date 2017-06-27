/*
Copyright 2017 SourceClear Inc
Licensed to the Apache Software Foundation (ASF) under one
or more contributor license agreements.  See the NOTICE file
distributed with this work for additional information
regarding copyright ownership.  The ASF licenses this file
to you under the Apache License, Version 2.0 (the
"License"); you may not use this file except in compliance
with the License.  You may obtain a copy of the License at
  http://www.apache.org/licenses/LICENSE-2.0
Unless required by applicable law or agreed to in writing,
software distributed under the License is distributed on an
"AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
KIND, either express or implied.  See the License for the
specific language governing permissions and limitations
under the License.
*/

package main

import (
	"log"
	//"strings"
	//"fmt"
	//"reflect"
	"time"

	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/ec2"
	//"github.com/aws/aws-sdk-go/service/iam"
	"github.com/aws/aws-sdk-go/service/rds"
)

type RDSBuilder struct{}

func (builder RDSBuilder) Name() string {
	return "RDS"
}

func (builder RDSBuilder) Populate(session *session.Session, tree *AWSTree) {
	svc := rds.New(session)
	svcr := ec2.New(session)
	dbInstance, err := svc.DescribeDBInstances(&rds.DescribeDBInstancesInput{})
	if err != nil {
		log.Fatalf("Couldn't list database instances: %v\n", err)
	}

	rdsData := RDSData{Databases: make([]DBInstances, 0, len(dbInstance.DBInstances))}

	for _, db := range dbInstance.DBInstances {
		rdsData.Databases = append(rdsData.Databases, *buildInstance(svc, db, svcr))
	}

	tree.Audit.RDS = &rdsData
}

func buildInstance(svc *rds.RDS, db *rds.DBInstance, svcr *ec2.EC2) *DBInstances {
	//To assign the details of db instances into struct DBInstances
	d := &DBInstances{}
	d.ARN = *db.DBInstanceArn
	d.DBInstanceIdentifier = *db.DBInstanceIdentifier
	d.CreatedAt = *db.InstanceCreateTime
	d.Encrypted = *db.StorageEncrypted
	d.SecGrpId = *db.VpcSecurityGroups[0].VpcSecurityGroupId

	buildSnapshot(svc, d)
	buildSecGrp(svcr, d)

	return d
}

func buildSnapshot(svc *rds.RDS, db *DBInstances) {
	snapshots, err := svc.DescribeDBSnapshots(&rds.DescribeDBSnapshotsInput{DBInstanceIdentifier: &db.DBInstanceIdentifier})
	if err != nil {
		log.Fatalf("Couldn't list snapshots: %v\n", err)
	}

	//To assign the details of snapshots into struct DBSnapshots
	for _, snapshot := range snapshots.DBSnapshots {
		s := DBSnapshots{ARN: *snapshot.DBSnapshotArn,
			DBInstanceIdentifier: *snapshot.DBInstanceIdentifier,
			DBSnapshotIdentifier: *snapshot.DBSnapshotIdentifier}

		db.Snapshots = append(db.Snapshots, s)
	}
}

func buildSecGrp(svcr *ec2.EC2, db *DBInstances) {
	secgrps, err := svcr.DescribeSecurityGroups(&ec2.DescribeSecurityGroupsInput{GroupIds: []*string{&db.SecGrpId}})
	if err != nil {
		log.Fatalf("Couldn't list security groups", err)
	}

	for _, sg := range secgrps.SecurityGroups {

		//To assign the details of security groups into struct DBSecGrps
		dbSecGrp := DBSecGrps{GroupId: *sg.GroupId,
			GroupName: *sg.GroupName,
			VpcId:     *sg.VpcId,
			Ingress:   make([]SecGroupsIngress, 0, len(sg.IpPermissions)),
			Egress:    make([]SecGroupsEgress, 0, len(sg.IpPermissionsEgress))}

		//To assign the details of ingress rules into struct SecGroupsIngress
		for _, ig := range sg.IpPermissions {
			ingress := SecGroupsIngress{FromPort: *ig.FromPort,
				Protocol: *ig.IpProtocol,
				IpRange:  make([]IngressIP, 0, len(ig.IpRanges)),
				ToPort:   *ig.ToPort}

			if ig.FromPort != nil {
				ingress.FromPort = *ig.FromPort
			}

			if ig.ToPort != nil {
				ingress.ToPort = *ig.ToPort
			}

			for _, igip := range ig.IpRanges {
				ingressIp := IngressIP{Ip: *igip.CidrIp}
				ingress.IpRange = append(ingress.IpRange, ingressIp)
			}

			dbSecGrp.Ingress = append(dbSecGrp.Ingress, ingress)
		}

		//To assign the details of egress rules into struct SecGroupsEgress
		for _, eg := range sg.IpPermissionsEgress {
			egress := SecGroupsEgress{Protocol: *eg.IpProtocol,
				IpRange: make([]EgressIP, 0, len(eg.IpRanges))}

			if eg.FromPort != nil {
				egress.FromPort = *eg.FromPort
			}

			if eg.ToPort != nil {
				egress.ToPort = *eg.ToPort
			}

			for _, egip := range eg.IpRanges {
				egressIp := EgressIP{Ip: *egip.CidrIp}

				egress.IpRange = append(egress.IpRange, egressIp)
			}

			dbSecGrp.Egress = append(dbSecGrp.Egress, egress)
		}

		db.SecurityGroups = append(db.SecurityGroups, dbSecGrp)
	}

}

// RDSData contains all RDS related data collected through the AWS account scan.
type RDSData struct {
	Databases []DBInstances `json:"dbInstances"`
}

// RDSUser represents a single IAM user, as collected through an AWS account scan.
/*type RDSUser struct {
	ARN  string `json:"arn"`
	Name string `json:"name"`
}*/

//DBInstance list the details of a db instance
type DBInstances struct {
	ARN                  string        `json:"arn"`
	DBInstanceIdentifier string        `json:"dbInstanceIdentifier"`
	CreatedAt            time.Time     `json:"createdTime"`
	Encrypted            bool          `json:"encrypted"`
	SecGrpId             string        `json:"secGrpId"`
	Snapshots            []DBSnapshots `json:"snapshots"`
	SecurityGroups       []DBSecGrps   `json:"securityGroups"`
}

//DBSnapshots list the details of snapshots related to a specific db instance
type DBSnapshots struct {
	ARN                  string `json:"dbSnapshotArn"`
	DBInstanceIdentifier string `json:"dbInstanceIdentifier"`
	DBSnapshotIdentifier string `json:"dbSnapshotIdentifier"`
	Encrypted            bool   `json:"encrypted"`
}

//DBSecGrps list the details of security groups related to a specific db instance
type DBSecGrps struct {
	GroupId   string             `json:"groupId"`
	GroupName string             `json:"groupname"`
	VpcId     string             `json:"vpcId"`
	Ingress   []SecGroupsIngress `json:"ingress"`
	Egress    []SecGroupsEgress  `json:"egress"`
}

//SecGrpsIngress list the ingress rules of security groups related to a specific db instance
type SecGroupsIngress struct {
	FromPort int64       `json:"fromPort"`
	Protocol string      `json:"protocol"`
	IpRange  []IngressIP `json:"ipRange"`
	ToPort   int64       `json:"toPort"`
}

//SecGrpsIngress list the egress rules of security groups related to a specific db instance
type SecGroupsEgress struct {
	FromPort int64      `json:"fromPort"`
	Protocol string     `json:"protocol"`
	IpRange  []EgressIP `json:"ipRange"`
	ToPort   int64      `json:"toPort"`
}

//IngressIP list the IP range for ingress rules
type IngressIP struct {
	Ip string `json:"CidrIp"`
}

//EgressIP list the IP range for egress rules
type EgressIP struct {
	Ip string `json:"CidrIp"`
}
