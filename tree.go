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

func NewTree() AWSTree {
	tree := AWSTree{}
	tree.Audit = AuditData{}
	return tree
}

// AWSTree represents a complete picture of an AWS account scan.
type AWSTree struct {
	Audit AuditData `json:"audit"`
}

// AuditData represents the data tree from an AWS audit.  It contains only raw
// data.  Policy data (and the derived from it) exist elsewhere.
type AuditData struct {
	IAM *IAMData `json:"iam"`
	RDS *RDSData `json:"rds"`
	//TODO: Create and fill in RDS, KMS, and EC2 data here.
}
