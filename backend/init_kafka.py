def zookeeper_cluster_config():
  """
  step 1.1 create zookeeper cluster config by passing(*) variables
  """
  airformex-kafka-zookeeper-config.yaml
  
  
def zookeeper_cluster_deploy():
  """
  step 1.2 deploy zookeeper cluster config by call config yaml file
  """
  kubectl create -f zookeeper_deploy.yaml
  kubectl get pods #view pods
  kubectl logs [POD_NAME] # to check with the logs
  
  
def zookeeper_service_config():
  """
  step 1.3 create zookeeper service config by passing(*) variables
  """
  airformex-kafka-zookeeper-service.yaml

  
def zookeeper_service_deploy():
  """
  step 1.4 deploy zookeeper service config by call config yaml file
  """
  kubectl create -f airformex-kafka-zookeeper-service.yaml
  kubectl get services # view services

  
def kafka_service_config():
  """
  step 2.1 create kafka service config by passing(*) variables
  """
  airformex-kafka-service-config.yaml
 

def kafka_service_deploy():
  """
  step 2.2 deploy kafka service by call config yaml file
  """
  kubectl create -f airformex-kafka-service-config.yaml
  kubectl get services # view services | collect resource information
  
  
def kafka_cluster_config():
  """
  step 2.3 create kafka cluster config by passing(*) variables
  """
  airformex-kafka-cluster-config.yaml
  
  
def kafka_cluster_deploy():
  """
  step 2.4 deploy kafka cluster by call config yaml file
  """
  kubectl create -f airformex-kafka-cluster-config.yaml
  kubectl get pod # view services
  
  
def test():
  ######
  
