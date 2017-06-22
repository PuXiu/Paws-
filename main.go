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
	"encoding/json"
	"fmt"
	"log"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
)

//
// TreeBuilder instances provide functionality that
// populates some portion of the Audit Tree.  These instances
// should focus in a single AWS service (IAM, RDS, EC2, KMS, etc)
// and must be carful not to overwrite other sections.
//
type TreeBuilder interface {

	//
	// Populate does as its name implies, it uses the supplied session and
	// uses it to query the AWS API and build out parts of the supplied AWSTree. This
	// method must either: 1) Populate its section of tree without fail or 2) On failure it
	// should call log.Fatalf() to print out an error message and exit the application.
	//
	Populate(session *session.Session, tree *AWSTree)

	//
	// Name returns the simple name of a TreeBuilder.  This will usually be
	// the name of the AWS service that it populates.
	//
	Name() string
}

func main() {

	// TODO: Put your EC2, RDS, and KMS Treebuilder instances here.
	builders := []TreeBuilder{IAMBuilder{},RDSBuilder{}}

	sess, err := session.NewSession(&aws.Config{
		// TODO: Jason to remove hardcoded region
		Region: aws.String("us-west-2")},
	)
	if err != nil {
		log.Fatalf("Couldn't set up session: %v\n", err)
	}

	tree := &AWSTree{Audit: AuditData{}}

	for _, builder := range builders {
		fmt.Printf("Querying %v\n", builder.Name())
		builder.Populate(sess, tree)
	}

	// Temporary debug output. Eventually we need to pull in our custom policies and
	// compare data <> policy.
	bytes, err := json.MarshalIndent(tree, "", "  ")
	fmt.Printf("\n%v\n", string(bytes))
}
