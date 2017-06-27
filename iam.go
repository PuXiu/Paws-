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
	"strings"
	"time"

	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/iam"
)

type IAMBuilder struct{}

func (builder IAMBuilder) Name() string {
	return "IAM"
}



func (builder IAMBuilder) Populate(session *session.Session, tree *AWSTree) {

	svc := iam.New(session)
	users, err := svc.ListUsers(&iam.ListUsersInput{})
	if err != nil {
		log.Fatalf("Couldn't list users: %v\n", err)
	}

	//
	// A slice of virtual MFAs is less than optimal.  Better to
	// map User Arn -> MFA.
	//
	vmfaMap := make(map[string]string)
	for _, mfa := range getVirtualMFAs(svc) {
		vmfaMap[*mfa.User.Arn] = *mfa.SerialNumber
	}

	iamData := IAMData{Users: make([]IAMUser, 0, len(users.Users))}

	for _, user := range users.Users {
		iamData.Users = append(iamData.Users, *buildUser(svc, user, vmfaMap))
	}

	tree.Audit.IAM = &iamData
}

func buildUser(svc *iam.IAM, user *iam.User, vmfaMap map[string]string) *IAMUser {
	u := &IAMUser{}
	u.ARN = *user.Arn
	u.CreatedAt = *user.CreateDate
	u.Path = *user.Path
	u.ID = *user.UserId
	u.Name = *user.UserName
	u.Keys = make([]IAMKey, 0, 1) // 1 is the conservative choice, we can always expand as needed.

	//
	// In order to find out when a password was created, we need to make another API call.  If the
	// user has no password, this method will return a 404.  This is OK and expected for API-only
	// users.
	//
	loginProfileOutput, err := svc.GetLoginProfile(&iam.GetLoginProfileInput{UserName: user.UserName})
	if err != nil && !strings.Contains(err.Error(), "404") {
		log.Fatalf("Couldn't get user login profile for %v: %v\n", user.UserName, err)
	}

	password := IAMUserPassword{}

	if loginProfileOutput.LoginProfile != nil && loginProfileOutput.LoginProfile.CreateDate != nil {
		password.CreatedAt = loginProfileOutput.LoginProfile.CreateDate
	}

	if user.PasswordLastUsed != nil {
		password.LastUsed = user.PasswordLastUsed
	}

	u.Password = password

	if len(vmfaMap[u.ARN]) > 0 {
		u.MFAType = "virtual"
	} else {
		u.MFAType = "none"
	}

	buildKeys(svc, u)

	return u
}

func buildKeys(svc *iam.IAM, user *IAMUser) {
	keys, err := svc.ListAccessKeys(&iam.ListAccessKeysInput{UserName: &user.Name})
	if err != nil {
		log.Fatalf("Couldn't list access keys: %v\n", err)
	}

	for _, key := range keys.AccessKeyMetadata {
		lastUsed, err := svc.GetAccessKeyLastUsed(&iam.GetAccessKeyLastUsedInput{AccessKeyId: key.AccessKeyId})
		if err != nil {
			log.Fatalf("Couldn't determine when key was last used: %v\n", err)
		}

		iamLastUsed := IAMLastUsed{}

		if lastUsed != nil && lastUsed.AccessKeyLastUsed != nil {
			klu := lastUsed.AccessKeyLastUsed
			if klu.LastUsedDate != nil {
				iamLastUsed.Date = *klu.LastUsedDate
				iamLastUsed.Region = *klu.Region
				iamLastUsed.ServiceName = *klu.ServiceName
			}
		}

		userKey := IAMKey{ID: *key.AccessKeyId,
			CreatedAt: *key.CreateDate,
			Status:    *key.Status,
			LastUsed:  iamLastUsed}
		// LastUsed: IAMLastUsed{Date: *lastUsed.AccessKeyLastUsed.LastUsedDate,
		// 	Region:      *lastUsed.AccessKeyLastUsed.Region,
		// 	ServiceName: *lastUsed.AccessKeyLastUsed.ServiceName}}
		user.Keys = append(user.Keys, userKey)
	}
}

//
// Query for all Virtual MFAs and return a slice.  The devices can
// be matched up with IAM users by looking at the User->Arn field.
//
func getVirtualMFAs(svc *iam.IAM) []*iam.VirtualMFADevice {

	maxItems := int64(1000)

	devices := make([]*iam.VirtualMFADevice, 0, 50)

	remaining := true
	marker := ""

	for remaining {
		var input iam.ListVirtualMFADevicesInput
		if len(marker) > 0 {
			input = iam.ListVirtualMFADevicesInput{Marker: &marker, MaxItems: &maxItems}
		} else {
			input = iam.ListVirtualMFADevicesInput{MaxItems: &maxItems}
		}

		output, err := svc.ListVirtualMFADevices(&input)
		if err != nil {
			log.Fatalf("Couldn't get Virtual MFA devices: %v\n", err)
		}

		devices = append(devices, output.VirtualMFADevices...)
		if output.Marker != nil {
			marker = *output.Marker
		}
		remaining = *output.IsTruncated
	}

	return devices
}

// IAMData contains all IAM related data collected through the AWS account scan.
type IAMData struct {
	Users []IAMUser `json:"users"`
}

// IAMUser represents a single IAM user, as collected through an AWS account scan.
type IAMUser struct {
	ARN       string          `json:"arn"`
	CreatedAt time.Time       `json:"createdAt"`
	Path      string          `json:"path"`
	ID        string          `json:"id"`
	Name      string          `json:"name"`
	MFAType   string          `json:"mfaType"`
	Keys      []IAMKey        `json:"keys"`
	Password  IAMUserPassword `json:"password"`
}

// IAMKey is an access key used by an AWS entity
type IAMKey struct {
	ID        string      `json:"id"`
	CreatedAt time.Time   `json:"createdAt"`
	Status    string      `json:"status"`
	LastUsed  IAMLastUsed `json:"lastUsed"`
}

type IAMLastUsed struct {
	Date        time.Time `json:"date"`
	Region      string    `json:"region"`
	ServiceName string    `json:"serviceName"`
}

type IAMUserPassword struct {
	CreatedAt *time.Time `json:"createdAt"`
	LastUsed  *time.Time `json:"lastUsed"`
}
