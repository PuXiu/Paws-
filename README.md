# PAWS - A new AWS Security Auditor project.
This is a new project from the Continuous Security group, and is not yet at an alpha state. More information and code coming soon...


## Getting up and running
To build and run paws, you'll need a few things installed locally:

1. A functional Go installation (https://golang.org/)
2. Glide (https://glide.sh)
3. AWS Audit Credentials for your account.

To get the AWS Credentials, the easiest way is to go to the IAM Console -> Users -> (Create New User) -> Add the Security Audit security group.

Create an access key for that user, and place the credentials in your ~/.aws/credentials file as such:

    [default]
    aws_access_key_id = {Access key id goes here}
    aws_secret_access_key = {Access key secret goes here}

## Building and running paws
This can be done with the following:

    glide install && go build && ./paws

If all is working you will see the JSON tree output (at this stage)