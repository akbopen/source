# init eks
# 
# reference:
# 1. https://boto3.amazonaws.com/v1/documentation/api/latest/index.html
# https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/eks.html
# 2. https://pypi.org/project/aws-cdk.aws-eks/
# 3. https://github.com/akbopen/kb/blob/master/deploy_eks.md


# Installation
## pip install boto3

import boto3

import lib.utils

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
from botocore.config import Config


my_config = Config(
#     region_name = 'us-west-2',
    signature_version = 'v4',
    retries = {
        'max_attempts': 10,
        'mode': 'standard'
    }
)

proxy_definitions = {
    'http': 'http://proxy.amazon.com:6502',
    'https': 'https://proxy.amazon.org:2010'
}

# associate_encryption_config()
# associate_identity_provider_config()
# can_paginate()
# create_addon()
# ## 
# create_cluster()


# create_fargate_profile()
# create_nodegroup()
# delete_addon()
# ## 
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

# ## 
# list_clusters()
# list_fargate_profiles()
# list_identity_provider_configs()
# list_nodegroups()
# list_tags_for_resource()

# ## 
# list_updates()
# tag_resource()


# untag_resource()
# update_addon()

# ## 
# update_cluster_config()
# update_cluster_version()

# update_nodegroup_config()
# update_nodegroup_version()

#####################
## helper functions

def attach_policy_to_role(policy_arn, role_name):
  """
    Attach the required Amazon EKS managed IAM policy to a role.
    e.g.
    aws iam attach-role-policy \
      --policy-arn arn:aws:iam::aws:policy/AmazonEKS_CNI_Policy \
      --role-name AirFormexEKSCNIRole
  """
  iam = boto3.client('iam')
  response = client.attach_role_policy(
    PolicyArn='arn:aws:iam::aws:policy/AmazonEKS_CNI_Policy',
    RoleName='AirFormexEKSCNIRole',
  )

  print(response)


@utils.passmein
def create_aws_vpc_stack():
  """ # step 1.1 Create an Amazon VPC with public and private subnets that meets Amazon EKS requirements.

  aws cloudformation create-stack \
    --stack-name airformex-eks-vpc-stack \
    --template-url https://s3.us-west-2.amazonaws.com/amazon-eks/cloudformation/2020-10-29/amazon-eks-vpc-private-subnets.yaml
 
  """
  pass



def get_policy_doc(config_file_name):
    """all config, cloudformation and template file are in backend/template."""
    ### ###
    return ‘backend/template’ + config_file_name
    

# 2. Create a cluster IAM role and attach the required Amazon EKS IAM managed policy to it. Kubernetes clusters managed by Amazon EKS make calls to other AWS services on your behalf to manage the resources that you use with the service.
@utils.passmein
def create_iam_role(eks_session, role_name, policy_file):
  """Create a cluster IAM role.
  
  aws iam create-role \
  --role-name AirFormexEKSClusterRole \
  --assume-role-policy-document file://"airformex-cluster-role-trust-policy.json"

  """
  role_name = 'AirFormexEKSClusterRole'
  policy_file = get_policy_doc(policy_file)
  return eks_session.iam().create_role(role_name, policy_file)


@utils.passmein
def attach_eks_iam():
  """attach the required Amazon EKS IAM managed policy to it.
  
  Attach the required Amazon EKS managed IAM policy to the role.
  aws iam attach-role-policy \
  --policy-arn arn:aws:iam::aws:policy/AmazonEKSClusterPolicy \
  --role-name AirFormexEKSClusterRole
  """
  pass


def create_cluster_role_trust_policy(policy_file):
  """ # step 1.2.1 create the required Amazon EKS IAM managed policy 
  policy_file=airformex-cluster-role-trust-policy.json
  """
  pass
  
  
def create_cluster_iam_role():
  """ # step 1.2.2 create cluster IAM role
  
   aws iam create-role \
     --role-name AirFormexEKSClusterRole \
     --assume-role-policy-document file://"airformex-cluster-role-trust-policy.json"

  """   

 
# Step 2: Configure to communicate with cluster
@utils.passmein
def create_kubeconfig():
  """
2.1. Create or update a kubeconfig file for cluster.
aws eks update-kubeconfig \
  --region ap-southeast-2 \
  --name AirFormex-EKS
  """
  pass


@utils.passmein
def test_kube():
  """
2.2. Test configuration
kubectl get svc
  """
  pass


# Step 3: Create IAM OpenID Connect (OIDC) provider

@utils.passmein
def test_kube():
  """
3. Create an IAM OpenID Connect (OIDC) provider for your cluster so that Kubernetes service accounts used by workloads can access AWS resources. You only need to complete this step one time for a cluster.
  """
  pass


# Step 4: Create nodes
@utils.passmein
def create_vpc_cni_role(role_name, role_policy_document):
  """
4.3.1 Create an IAM role for the Amazon VPC CNI plugin.
aws iam create-role \
  --role-name AirFormexEKSCNIRole \
  --assume-role-policy-document file://"airformex-cni-role-trust-policy.json"
  """
  pass


@utils.passmein
def attach_policy_to_cni_role(policy_arn, role_name):
  """
3.2 Attach the required Amazon EKS managed IAM policy to the role.
aws iam attach-role-policy \
  --policy-arn arn:aws:iam::aws:policy/AmazonEKS_CNI_Policy \
  --role-name AirFormexEKSCNIRole
  """
  response = attach_policy_to_role(policy_arn='arn:aws:iam::aws:policy/AmazonEKS_CNI_Policy', role_name='AirFormexEKSCNIRole')


@utils.passmein
def associate_svc_to_role(policy_arn, role_name):
  """
3.2. Associate the Kubernetes service account used by the VPC CNI plugin to the IAM role.
  """
  pass


@utils.passmein
def create_node_role(policy_arn, role_name):
  """
4.3. Create a node IAM role and attach the required Amazon EKS IAM managed policy to it.
b. Create the node IAM role.
aws iam create-role \
  --role-name AirFormexEKSNodeRole \
  --assume-role-policy-document file://"airformex-node-role-trust-policy.json"
  """
  pass

@utils.passmein
def attach_policy_to_node_role(policy_arn, role_name):
  """3.3 Attach the required Amazon EKS managed IAM policies to the role.
    aws iam attach-role-policy \
      --policy-arn arn:aws:iam::aws:policy/AmazonEKSWorkerNodePolicy \
      --role-name AirFormexEKSNodeRole

    aws iam attach-role-policy \
      --policy-arn arn:aws:iam::aws:policy/AmazonEC2ContainerRegistryReadOnly \
      --role-name AirFormexEKSNodeRole
  """
  response = attach_policy_to_role(policy_arn='arn:aws:iam::aws:policy/AmazonEKSWorkerNodePolicy', role_name='AirFormexEKSNodeRole')
  response = attach_policy_to_role(policy_arn='arn:aws:iam::aws:policy/AmazonEC2ContainerRegistryReadOnly', role_name='AirFormexEKSNodeRole')


  @utils.passmein
  def add_node_group():
    """4.3.
    7. On the Configuration tab, select the Compute tab, and then choose Add Node Group.
    8. On the Configure node group page, fill out the parameters accordingly, accept the remaining default values, and then choose Next.
Name – Enter a unique name for your managed node group, AirFormex-EKS-Nodegroup.
Node IAM role name – Choose AirFormexEKSNodeRole. In this getting started guide, this role must only be used for this node group and no other node groups.
10. On the Specify networking page, select an existing key pair to use for SSH key pair and then choose Next.
aws ec2 create-key-pair --region ap-southeast-2 --key-name AirFormexKeyPair
    """
    pass
  
  # 12. After several minutes, the Status in the Node Group configuration section will change from Creating to Active. Don't continue to the next step until the status is Active.
  
@utils.passmein 
def create_eks_cluster(cluster_name, roleArn, resourcesVpcConfig, kubernetesNetworkConfig, logging, clientRequestToken, tags, encryptionConfig):
    """Create EKS cluster."""
    response = client.create_cluster(
        name=cluster_name,   # 'AirFormex-EKS',
        # version='string',  # Kubernetes version, optional, default latest version.
        roleArn='string',  # The Amazon Resource Name (ARN) of the IAM role that provides permissions for the Kubernetes control plane to make calls to AWS API operations on your behalf. 
        resourcesVpcConfig={  # read from https://github.com/akbopen/source/blob/main/backend/config/amazon-eks-vpc-private-subnets.yaml
            'subnetIds': [
                'string', # 
            ],
            'securityGroupIds': [
                'string', # 
            ],
            'endpointPublicAccess': True, # |False,
            'endpointPrivateAccess': True, # |False,
            'publicAccessCidrs': [
                'string',  # 
            ]
        },
        kubernetesNetworkConfig={  # The Kubernetes network configuration for the cluster.
            'serviceIpv4Cidr': 'string'
        },
        logging={  # Enable or disable exporting the Kubernetes control plane logs for your cluster to CloudWatch Logs. By default, cluster control plane logs aren't exported to CloudWatch Logs
            'clusterLogging': [
                {
                    'types': [
                        'api', # |'audit'|'authenticator'|'controllerManager'|'scheduler',
                    ],
                    'enabled': True
                },
            ]
        },
        clientRequestToken='string',   # read from env/config
        tags={
            'string': 'string'
        },
        encryptionConfig=[
            {
                'resources': [
                    'string',
                ],
                'provider': {
                    'keyArn': 'string'
                }
            },
        ]
    )

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

    
@utils.passmein
def list_clusters(max_clusters=10, iter_marker=''):
    """List the Amazon EKS clusters in the AWS account's default region.
    :param max_clusters: Maximum number of clusters to retrieve.
    :param iter_marker: Marker used to identify start of next batch of clusters to retrieve
    :return: List of cluster names
    :return: String marking the start of next batch of clusters to retrieve. Pass this string as the iter_marker
        argument in the next invocation of list_clusters().
    """

    eks = boto3.client('eks')

    clusters = eks.list_clusters(maxResults=max_clusters, nextToken=iter_marker)
    marker = clusters.get('nextToken')       # None if no more clusters to retrieve
    return clusters['clusters'], marker
  
  
def attach_role_policy(): 
   """
   Step 1.2.3 Attach the required Amazon EKS managed IAM policy to the role.
   aws iam attach-role-policy \
     --policy-arn arn:aws:iam::aws:policy/AmazonEKSClusterPolicy \
     --role-name AirFormexEKSClusterRole
   """
    
    
def create_eks_cluster():
   """
   Step 2.1 create_eks_cluster
   Null, currently creating via Console UI
   """
 
    
def kubeconfig_update():
  """
  Step 2.2  Create or update a kubeconfig file for cluster.
  aws eks update-kubeconfig \
    --region ap-southeast-2 \
    --name AirFormex-EKS
  """
  

def post_eks_create_test():
  """ 
  step 2.3 Test configuration
  kubectl get svc 
  # Need to collect output, will have to use SDK handler
  """
 

def create_openid_connect_provider():
  """
  Step 2.4 create an IAM OpenID Connect (OIDC) provider, need to scope SDK
  
  Current option, manual via Console:
  1. Hit Configuration from EKS cluster
  2. Copy value for OpenID Connect provider URL
  3. Add IAM Identity provider with OpenID Connect, give URL from EKS cluster
  4. Enable thumbprint
  5. Add sts.amazonaws.com for Audience
  """
  

# Following for eks node creation 
def create_vpc_cni_plugin_iam_role():
    """ 
    Step 4.1 Create an IAM role for the Amazon VPC CNI plugin
    aws iam create-role \
  --role-name AirFormexEKSCNIRole \
  --assume-role-policy-document file://"airformex-cni-role-trust-policy.json"
    """
   
def attach_vpc_cni_trust_policy_to_eks_iam_role():
    """
    Step 4.2
    aws iam attach-role-policy \
  --policy-arn arn:aws:iam::aws:policy/AmazonEKS_CNI_Policy \
  --role-name AirFormexEKSCNIRole
    """
  
def associate_eks_account_to_eks_iam_role():
    """
    aws eks update-addon \
  --cluster-name AirFormex-EKS \
  --addon-name vpc-cni \
  --service-account-role-arn arn:aws:iam::213397327449:role/AirFormexEKSCNIRole 
    """

def create_node_iam_role():
    """
    aws iam create-role \
  --role-name AirFormexEKSNodeRole \
  --assume-role-policy-document file://"airformex-node-role-trust-policy.json"
    """

def attach_eks_management_policy_to_eks_iam_role():
    """
    Step 4.3
    aws iam attach-role-policy \
  --policy-arn arn:aws:iam::aws:policy/AmazonEKSWorkerNodePolicy \
  --role-name AirFormexEKSNodeRole
aws iam attach-role-policy \
  --policy-arn arn:aws:iam::aws:policy/AmazonEC2ContainerRegistryReadOnly \
  --role-name AirFormexEKSNodeRole
    """
    
 
def create_eks_node_group():
    """
    Step 4.4 - 4.9 currently manual actions via Console, need to scope SDK
    """


def create_ec2_keypair():
    """
    Step 4.10
    aws ec2 create-key-pair --region ap-southeast-2 --key-name AirFormexKeyPair
    """
   
def node_post_check():
    """
    Step 4.11 review resource, polling stage
    """"
    


  def main():

    # Init EKS client
    client = boto3.client('eks', config=my_config)
 
    # create cluster
    resourcesVpcConfig = create_aws_vpc()
    create_iam_role()
    attach_eks_iam()
    create_kubeconfig()
    test_kube()
    
    create_vpc_cni_role(role_name, role_policy_document)
    attach_policy_to_cni_role(policy_arn, role_name)
    associate_svc_to_role(policy_arn, role_name)
    create_node_role(policy_arn, role_name)
    attach_policy_to_node_role(policy_arn, role_name):
    add_node_group():
    
    response = create_eks_cluster(cluster_name='AirFormex-EKS', roleArn, resourcesVpcConfig, kubernetesNetworkConfig, logging, clientRequestToken, tags, encryptionConfig)
    # list cluster  
    clusters, marker = list_clusters()
    if not clusters:
        print('No clusters exist.')
    else:
        while True:
            # Print cluster names
            for cluster in clusters:
                print(cluster)

            # If no more clusters exist, exit loop, otherwise retrieve the next batch
            if marker is None:
                break
            clusters, marker = list_clusters(iter_marker=marker)

# def kubeconfig_update():
# def post_eks_create_test():
# def create_openid_connect_provider():
# def create_vpc_cni_plugin_iam_role():
# def attach_vpc_cni_trust_policy_to_eks_iam_role():
# def associate_eks_account_to_eks_iam_role():
# def create_node_iam_role():
# def attach_eks_management_policy_to_eks_iam_role():
# def create_eks_node_group():
# def create_ec2_keypair():
# def node_post_check():
            
if __name__ == '__main__':
    main()



