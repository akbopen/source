import boto3
import uuid
from source.backend.helpers import *

# define boto3 client
eksclient = boto3.client('eks')
iamclient = boto3.client('iam')
cfnclient = boto3.client('cloudformation')

# Set up the client
ekssession = boto3.Session(region_name=REGION_NAME)
eks = ekssession.client('eks')


# define aws config
my_config = Config(
    region_name = 'us-west-2',
    signature_version = 'v4',
    retries = {'max_attempts': 10, 'mode': 'standard'}
)

# define proxy ?
proxy_definitions = {
    'http': 'http://proxy.amazon.com:6502',
    'https': 'https://proxy.amazon.org:2010'
}


CFN_STACK_NAME = 'airformex-eks-vpc-stack'
CFN_TEMP_URL = 'https://s3.us-west-2.amazonaws.com/amazon-eks/cloudformation/2020-10-29/amazon-eks-vpc-private-subnets.yaml'
ROLE_TRUST_POLICY_NAME = 'airformex-cluster-role-trust-policy'
ROLE_TRUST_POLICY_FILE = 'airformex-cluster-role-trust-policy.json'
ROLE_NAME = 'AirFormexEKSClusterRole'
ROLE_POLICY_DOC = 'airformex-cluster-role-trust-policy.json'
ROLE_POLICY_NAME = 'arn:aws:iam::aws:policy/AmazonEKSClusterPolicy'
EKS_CLUSTER_NAME = 'AirFormex-EKS'
EKS_CLUSTER_VERSION = 'string' # optional
EKS_CLUSTER_ROLE_ARN = ''
EKS_CLUSTER_RESOURCE_VPC = 'amazon-eks-vpc-private-subnets.yaml'
MAX_CLUSTERS = 10
ITER_MAKER = ''
REGION_NAME = 'ap-southeast-2'
CNI_ROLE_POLICY_DOC = 'airformex-cni-role-trust-policy.json'
CNI_ROLE_NAME = 'AirFormexEKSCNIRole'
CNI_ROLE_POLICY_NAME = 'arn:aws:iam::aws:policy/AmazonEKS_CNI_Policy'
CNI_ROLE_ARN = 'arn:aws:iam::213397327449:role/AirFormexEKSCNIRole'
EKS_CLUSTER_NODE_ROLE = 'AirFormexEKSNodeRole'
EKS_CLUSTER_NODE_ROLE_POLICY_DOC = 'airformex-node-role-trust-policy.json'
EKS_CLUSTER_NODE_ROLE_WORKER_POLICY_ARN = 'arn:aws:iam::aws:policy/AmazonEKSWorkerNodePolicy'
EKS_CLUSTER_NODE_ROLE_CONTAINER_POLICY_ARN = 'arn:aws:iam::aws:policy/AmazonEC2ContainerRegistryReadOnly'
KEY_NAME = 'AirFormexKeyPair'


def get_policy_doc(config_file_name):
    return 'backend/template' + config_file_name


@utils.passmein
def create_aws_vpc_stack(cfnclient, CFN_STACK_NAME, CFN_TEMP_URL):
  response = cfnclient.create_stack(
     StackName=CFN_STACK_NAME,
     TemplateURL=CFN_TEMP_URL,
  )
  print(response)


@utils.passmein
def create_cluster_role_trust_policy(
    iamclient,
    ROLE_TRUST_POLICY_NAME,
    ROLE_TRUST_POLICY_FILE
):
    response = iamclient.create_policy(
        PolicyName=ROLE_TRUST_POLICY_NAME,
        policy_file=ROLE_TRUST_POLICY_FILE,
   )
   print(response)


@utils.passmein
def create_iam_role(iamclient, ROLE_NAME, ROLE_POLICY_DOC):
  response = iamclient.create_role(ROLE_NAME, ROLE_POLICY_DOC)
     RoleName=ROLE_NAME,
     AssumeRolePolicyDocument=ROLE_POLICY_DOC,
  )


@utils.passmein
def attach_eks_iam(iamclient, ROLE_NAME, ROLE_POLICY_NAME):
  response = iamclient.attach_role_policy(ROLE_NAME, ROLE_POLICY_NAME)
    RoleName=ROLE_NAME,
    PolicyArn=ROLE_POLICY_NAME,
   )


@utils.passmein
def create_eks_cluster(
    eksclient,
    EKS_CLUSTER_NAME,
    EKS_CLUSTER_VERSION,
    EKS_CLUSTER_ROLE_ARN,
    EKS_CLUSTER_RESOURCE_VPC,
):
    response = eksclient.create_cluster( # details see bottom Appendix: Response Syntax
        name=EKS_CLUSTER_NAME,
        version=EKS_CLUSTER_VERSION,
        roleArn=EKS_CLUSTER_ROLE_ARN,  # The Amazon Resource Name (ARN) of the IAM role that provides permissions for the Kubernetes control plane to make calls to AWS API operations on your behalf.
        resourcesVpcConfig=EKS_CLUSTER_RESOURCE_VPC
    )


@utils.passmein
def list_clusters(eksclient, MAX_CLUSTERS, ITER_MAKER):
    clusters = eksclient.list_clusters(maxResults=MAX_CLUSTERS, nextToken=ITER_MAKER)
    marker = clusters.get('nextToken')       # None if no more clusters to retrieve
    return clusters['clusters'], marker


@utils.passmein
def create_kubeconfig():
    aws eks update-kubeconfig \
    --region ap-southeast-2 \
    --name AirFormex-EKS
  pass


# get cluster details
cluster = eks.describe_cluster(name=EKS_CLUSTER_NAME)
cluster_cert = cluster["cluster"]["certificateAuthority"]["data"]
cluster_ep = cluster["cluster"]["endpoint"]
        

@utils.passmein
def test_kube():
  """
  kubectl get svc
  """
  pass

  
@utils.passmein
def create_openid_connect_provider():
  pass


@utils.passmein
def create_vpc_cni_role(iamclient, CNI_ROLE_NAME, CNI_ROLE_POLICY_DOC):
  response = iamclient.create_role(
     RoleName=CNI_ROLE_NAME,
     AssumeRolePolicyDocument=CNI_ROLE_POLICY_DOC,
  )


@utils.passmein
def attach_policy_to_cni_role(CNI_ROLE_NAME, CNI_ROLE_POLICY_NAME):
  response = attach_policy_to_role(
     policy_arn=CNI_ROLE_POLICY_NAME,
     role_name=CNI_ROLE_NAME
  )


@utils.passmein
def associate_svc_to_role(CNI_ROLE_ARN, EKS_CLUSTER_NAME):
  aws eks update-addon \
  --cluster-name EKS_CLUSTER_NAME \
  --addon-name vpc-cni \
  --service-account-role-arn CNI_ROLE_ARN
  pass


@utils.passmein
def create_node_role(EKS_CLUSTER_NODE_ROLE, EKS_CLUSTER_NODE_ROLE_POLICY_DOC):
  response = client.create_role(
     RoleName=EKS_CLUSTER_NODE_ROLE,
     AssumeRolePolicyDocument=EKS_CLUSTER_NODE_ROLE_POLICY_DOC,
  )


@utils.passmein
def attach_policy_to_node_role(
    EKS_CLUSTER_NODE_ROLE,
    EKS_CLUSTER_NODE_ROLE_WORKER_POLICY_ARN,
    EKS_CLUSTER_NODE_ROLE_CONTAINER_POLICY_ARN,
):
  response = attach_policy_to_role(
      policy_arn=EKS_CLUSTER_NODE_ROLE_WORKER_POLICY_ARN,
      role_name=EKS_CLUSTER_NODE_ROLE
  )
  response = attach_policy_to_role(
      policy_arn=EKS_CLUSTER_NODE_ROLE_CONTAINER_POLICY_ARN,
      role_name=EKS_CLUSTER_NODE_ROLE
  )


def create_eks_node_group():
    pass


def create_ec2_keypair(REGION_NAME, KEY_NAME):
    aws ec2 create-key-pair --region REGION_NAME --key-name KEY_NAME
    pass


def node_post_check():
    pass


def main():
    # create cluster
    resourcesVpcConfig = create_aws_vpc_stack(cfnclient, CFN_STACK_NAME, CFN_TEMP_URL)
    
    create_cluster_role_trust_policy(iamclient, ROLE_TRUST_POLICY_NAME, ROLE_TRUST_POLICY_FILE)
    
    create_iam_role(iamclient, ROLE_NAME, ROLE_POLICY_DOC)
    
    attach_eks_iam(iamclient, ROLE_NAME, ROLE_POLICY_NAME)
    
    response = create_eks_cluster(eksclient, EKS_CLUSTER_NAME, EKS_CLUSTER_VERSION, EKS_CLUSTER_ROLE_ARN, EKS_CLUSTER_RESOURCE_VPC)
    
    clusters, marker = list_clusters(eksclient, MAX_CLUSTERS, ITER_MAKER)
    
    create_kubeconfig()
    
    test_kube()
    
    kubeconfig_update():
    
    create_openid_connect_provider():
    
    create_vpc_cni_role(iamclient, CNI_ROLE_NAME, CNI_ROLE_POLICY_DOC)
    
    attach_policy_to_cni_role(CNI_ROLE_NAME, CNI_ROLE_POLICY_NAME)
    
    associate_svc_to_role(CNI_ROLE_ARN, EKS_CLUSTER_NAME)
    
    create_node_role(EKS_CLUSTER_NODE_ROLE, EKS_CLUSTER_NODE_ROLE_POLICY_DOC)
    
    attach_policy_to_node_role(
    EKS_CLUSTER_NODE_ROLE,
    EKS_CLUSTER_NODE_ROLE_WORKER_POLICY_ARN,
    EKS_CLUSTER_NODE_ROLE_CONTAINER_POLICY_ARN,
)
    
    create_eks_node_group()
    
    create_ec2_keypair(REGION_NAME, KEY_NAME)
    
    node_post_check()

if __name__ == '__main__':
    main()


# init eks
#
# reference:
# 1. https://boto3.amazonaws.com/v1/documentation/api/latest/index.html
# https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/eks.html
# 2. https://pypi.org/project/aws-cdk.aws-eks/
# 3. https://github.com/akbopen/kb/blob/master/deploy_eks.md

# Installation
## pip install boto3

# Using environment variables
## Set configuration settings using system-wide environment variables. These configurations are global and will affect all clients created unless you override them with a Config object.
# AWS_ACCESS_KEY_ID
# The access key for your AWS account.
# AWS_SECRET_ACCESS_KEY
# The secret key for your AWS account.
# AWS_SESSION_TOKEN
# The session key for your AWS account. This is only needed when you are using temporary credentials. The AWS_SECURITY_TOKEN environment variable can also be used, but is only supported for backward-compatibility purposes. AWS_SESSION_TOKEN is supported by multiple AWS SDKs in addition to Boto3.
# AWS_DEFAULT_REGION
# The default AWS Region to use, for example, us-west-1 or us-west-2.
# AWS_PROFILE
# The default profile to use, if any. If no value is specified, Boto3 attempts to search the shared credentials file and the config file for the default profile.
# AWS_CONFIG_FILE
# The location of the config file used by Boto3. By default this value is ~/.aws/config. You only need to set this variable if you want to change this location.

# Configuation
## https://boto3.amazonaws.com/v1/documentation/api/latest/guide/quickstart.html#installation

# def passmein(func):
#     def wrapper(*args, **kwargs):
#         return func(func, *args, **kwargs)
#     return wrapper

#####################
## helper functions
# associate_encryption_config()
# associate_identity_provider_config()
# can_paginate()
# create_addon()
# create_cluster()
# create_fargate_profile()
# create_nodegroup()
# delete_addon()
# delete_cluster()
# delete_fargate_profile()
# delete_nodegroup()
# describe_addon()
# describe_addon_versions()
# describe_cluster()
# describe_fargate_profile()
# describe_identity_provider_config()
# describe_nodegroup()
# describe_update()
# disassociate_identity_provider_config()
# generate_presigned_url()
# get_paginator()
# get_waiter()
# list_addons()
# list_clusters()
# list_fargate_profiles()
# list_identity_provider_configs()
# list_nodegroups()
# list_tags_for_resource()
# list_updates()
# tag_resource()
# untag_resource()
# update_addon()
# update_cluster_config()
# update_cluster_version()
# update_nodegroup_config()
# update_nodegroup_version()


Appendix 
    # Response Syntax

    # {
    #     'cluster': {
    #         'name': 'string',
    #         'arn': 'string',
    #         'createdAt': datetime(2015, 1, 1),
    #         'version': 'string',
    #         'endpoint': 'string',
    #         'roleArn': 'string',
    #         'resourcesVpcConfig': {
    #             'subnetIds': [
    #                 'string',
    #             ],
    #             'securityGroupIds': [
    #                 'string',
    #             ],
    #             'clusterSecurityGroupId': 'string',
    #             'vpcId': 'string',
    #             'endpointPublicAccess': True|False,
    #             'endpointPrivateAccess': True|False,
    #             'publicAccessCidrs': [
    #                 'string',
    #             ]
    #         },
    #         'kubernetesNetworkConfig': {
    #             'serviceIpv4Cidr': 'string'
    #         },
    #         'logging': {
    #             'clusterLogging': [
    #                 {
    #                     'types': [
    #                         'api'|'audit'|'authenticator'|'controllerManager'|'scheduler',
    #                     ],
    #                     'enabled': True|False
    #                 },
    #             ]
    #         },
    #         'identity': {
    #             'oidc': {
    #                 'issuer': 'string'
    #             }
    #         },
    #         'status': 'CREATING'|'ACTIVE'|'DELETING'|'FAILED'|'UPDATING',
    #         'certificateAuthority': {
    #             'data': 'string'
    #         },
    #         'clientRequestToken': 'string',
    #         'platformVersion': 'string',
    #         'tags': {
    #             'string': 'string'
    #         },
    #         'encryptionConfig': [
    #             {
    #                 'resources': [
    #                     'string',
    #                 ],
    #                 'provider': {
    #                     'keyArn': 'string'
    #                 }
    #             },
    #         ]
    #     }
    # }

    
# build the cluster config hash
# cluster_config = {
#         "apiVersion": "v1",
#         "kind": "Config",
#         "clusters": [
#             {
#                 "cluster": {
#                     "server": str(cluster_ep),
#                     "certificate-authority-data": str(cluster_cert)
#                 },
#                 "name": "kubernetes"
#             }
#         ],
#         "contexts": [
#             {
#                 "context": {
#                     "cluster": "kubernetes",
#                     "user": "aws"
#                 },
#                 "name": "aws"
#             }
#         ],
#         "current-context": "aws",
#         "preferences": {},
#         "users": [
#             {
#                 "name": "aws",
#                 "user": {
#                     "exec": {
#                         "apiVersion": "client.authentication.k8s.io/v1alpha1",
#                         "command": "heptio-authenticator-aws",
#                         "args": [
#                             "token", "-i", cluster_name
#                         ]
#                     }
#                 }
#             }
#         ]
#     }

# # Write in YAML.
# config_text=yaml.dump(cluster_config, default_flow_style=False)
# open(config_file, "w").write(config_text)
