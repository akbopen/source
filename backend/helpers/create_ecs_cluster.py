# Copyright 2010-2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
#
# This file is licensed under the Apache License, Version 2.0 (the "License").
# You may not use this file except in compliance with the License. A copy of the
# License is located at
#
# http://aws.amazon.com/apache2.0/
#
# This file is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS
# OF ANY KIND, either express or implied. See the License for the specific
# language governing permissions and limitations under the License.

import boto3

# Create ECS client
try:
  ecs_client = boto3.client('ecs')
  
  response = ecs_client.create_cluster(
    clusterName='CLUSTER_NAME'
  )
  print(response)

except BaseException as exe:
    print(exe)

