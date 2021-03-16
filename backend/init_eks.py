# init eks
# https://pypi.org/project/aws-cdk.aws-eks/
# https://github.com/akbopen/kb/blob/master/deploy_eks.md


def create_aws_vpc_stack():
  """ #step 1.1 Create an Amazon VPC with public and private subnets that meets Amazon EKS requirements.

  aws cloudformation create-stack \
    --stack-name airformex-eks-vpc-stack \
    --template-url https://s3.us-west-2.amazonaws.com/amazon-eks/cloudformation/2020-10-29/amazon-eks-vpc-private-subnets.yaml
 
  """
  pass
  

def create_cluster_role_trust_policy():
  """ # step 1.2.1 create the required Amazon EKS IAM managed policy 
  file name: airformex-cluster-role-trust-policy.json
  file content:
  
  {
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "Service": "eks.amazonaws.com"
      },
      "Action": "sts:AssumeRole"
    }
   ]
  }
  """
  
  
def create_cluster_iam_role():
  """ # step 1.2.2 create cluster IAM role
  
   aws iam create-role \
     --role-name AirFormexEKSClusterRole \
     --assume-role-policy-document file://"airformex-cluster-role-trust-policy.json"

  """   

 
def attach_role_policy(): 
   """ # step 1.2.3 Attach the required Amazon EKS managed IAM policy to the role.
   aws iam attach-role-policy \
     --policy-arn arn:aws:iam::aws:policy/AmazonEKSClusterPolicy \
     --role-name AirFormexEKSClusterRole
   """
    
    
def create_eks_cluster():
   """ # step 2.1 create_eks_cluster
   Null, currently creating via Console UI
   """
    
    
def kubeconfig_update():
  """ # step 2.2  Create or update a kubeconfig file for cluster.
  aws eks update-kubeconfig \
    --region ap-southeast-2 \
    --name AirFormex-EKS

  """
  
 
def post_eks_create_test():
  """
  kubectl get svc # Need to collect output, will have to use SDK handler
  """
 

def create_openid_connect_provider():
  """
  
  """
  
  
def 
  
