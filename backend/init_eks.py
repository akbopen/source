my_config = Config(
    region_name = 'us-west-2',
    signature_version = 'v4',
    retries = {
        'max_attempts': 10,
        'mode': 'standard'
    },

)

proxy_definitions = {
    'http': 'http://proxy.amazon.com:6502',
    'https': 'https://proxy.amazon.org:2010'
}


def get_policy_doc(config_file_name):
    """all config, cloudformation and template file are in backend/template."""
    ### ###
    return 'backend/template' + config_file_name


@utils.passmein
def create_aws_vpc_stack():
  client = boto3.client('cloudformation')
  response = client.create_stack(
     StackName='airformex-eks-vpc-stack',
     TemplateURL='https://s3.us-west-2.amazonaws.com/amazon-eks/cloudformation/2020-10-29/amazon-eks-vpc-private-subnets.yaml',
  )
  print(response)


@utils.passmein
def create_cluster_role_trust_policy(policy_file):
    response = client.create_policy(
        PolicyName='airformex-cluster-role-trust-policy',
        policy_file=airformex-cluster-role-trust-policy.json


@utils.passmein
def create_iam_role(eks_session, role_name, policy_file):
  response = client.create_role(
     RoleName='AirFormexEKSClusterRole',
     AssumeRolePolicyDocument='file://"airformex-cluster-role-trust-policy.json"',
  )


@utils.passmein
def attach_eks_iam():
  response = client.attach_role_policy(
    RoleName='AirFormexEKSClusterRole',
    PolicyArn='arn:aws:iam::aws:policy/AmazonEKSClusterPolicy'
   )


@utils.passmein
def create_eks_cluster(cluster_name, roleArn, resourcesVpcConfig, kubernetesNetworkConfig, logging, clientRequestToken, tags, encryptionConfig):
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
    eks = boto3.client('eks')

    clusters = eks.list_clusters(maxResults=max_clusters, nextToken=iter_marker)
    marker = clusters.get('nextToken')       # None if no more clusters to retrieve
    return clusters['clusters'], marker


@utils.passmein
def create_kubeconfig():
    aws eks update-kubeconfig \
    --region ap-southeast-2 \
    --name AirFormex-EKS
  pass

      
@utils.passmein
def update_kubeconfig():
# Set up the client
s = boto3.Session(region_name=region)
eks = s.client("eks")

# get cluster details
cluster = eks.describe_cluster(name=cluster_name)
cluster_cert = cluster["cluster"]["certificateAuthority"]["data"]
cluster_ep = cluster["cluster"]["endpoint"]

# build the cluster config hash
cluster_config = {
        "apiVersion": "v1",
        "kind": "Config",
        "clusters": [
            {
                "cluster": {
                    "server": str(cluster_ep),
                    "certificate-authority-data": str(cluster_cert)
                },
                "name": "kubernetes"
            }
        ],
        "contexts": [
            {
                "context": {
                    "cluster": "kubernetes",
                    "user": "aws"
                },
                "name": "aws"
            }
        ],
        "current-context": "aws",
        "preferences": {},
        "users": [
            {
                "name": "aws",
                "user": {
                    "exec": {
                        "apiVersion": "client.authentication.k8s.io/v1alpha1",
                        "command": "heptio-authenticator-aws",
                        "args": [
                            "token", "-i", cluster_name
                        ]
                    }
                }
            }
        ]
    }

# Write in YAML.
config_text=yaml.dump(cluster_config, default_flow_style=False)
open(config_file, "w").write(config_text)

        

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
def create_vpc_cni_role(role_name, role_policy_document):
  response = client.create_role(
     RoleName='AirFormexEKSCNIRole',
     AssumeRolePolicyDocument='file://"airformex-cni-role-trust-policy.json"',
  )
  

@utils.passmein
def attach_policy_to_cni_role(policy_arn, role_name):
  response = attach_policy_to_role(
     policy_arn='arn:aws:iam::aws:policy/AmazonEKS_CNI_Policy',
     role_name='AirFormexEKSCNIRole'
  )


@utils.passmein
def associate_svc_to_role(policy_arn, role_name):
  aws eks update-addon \
  --cluster-name AirFormex-EKS \
  --addon-name vpc-cni \
  --service-account-role-arn arn:aws:iam::213397327449:role/AirFormexEKSCNIRole 
  pass


@utils.passmein
def create_node_role(policy_arn, role_name):
  response = client.create_role(
     RoleName='AirFormexEKSNodeRole',
     AssumeRolePolicyDocument='file://"airformex-node-role-trust-policy.json"',
  )


@utils.passmein
def attach_policy_to_node_role(policy_arn, role_name):
  response = attach_policy_to_role(policy_arn='arn:aws:iam::aws:policy/AmazonEKSWorkerNodePolicy', role_name='AirFormexEKSNodeRole')
  response = attach_policy_to_role(policy_arn='arn:aws:iam::aws:policy/AmazonEC2ContainerRegistryReadOnly', role_name='AirFormexEKSNodeRole')


def create_eks_node_group():
    pass


def create_ec2_keypair():
    aws ec2 create-key-pair --region ap-southeast-2 --key-name AirFormexKeyPair
    pass


def node_post_check():
    pass


def main():

    # Init EKS client
    client = boto3.client('eks', config=my_config)

    # create cluster
    resourcesVpcConfig = create_aws_vpc_stack()
    create_iam_role()
    attach_eks_iam()
    create_kubeconfig()
    test_kube()

    create_vpc_cni_role(role_name, role_policy_document)
    attach_policy_to_cni_role(policy_arn, role_name)
    associate_svc_to_role(policy_arn, role_name)
    create_node_role(policy_arn, role_name)
    attach_policy_to_node_role(policy_arn, role_name)
    add_node_group()

    response = create_eks_cluster(
      cluster_name='AirFormex-EKS',
      roleArn=roleArn,
      resourcesVpcConfig=resourcesVpcConfig,
      kubernetesNetworkConfig=kubernetesNetworkConfig,
      logging=logging,
      clientRequestToken=clientRequestToken,
      tags=tags,
      encryptionConfig=encryptionConfig)
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

    kubeconfig_update():
    create_openid_connect_provider():
    create_vpc_cni_plugin_iam_role():
    attach_vpc_cni_trust_policy_to_eks_iam_role():
    associate_eks_account_to_eks_iam_role():
    create_node_iam_role():
    attach_eks_management_policy_to_eks_iam_role():
    create_eks_node_group():
    create_ec2_keypair():
    node_post_check():

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
