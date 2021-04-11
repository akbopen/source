
# python3 -m venv .env
source .env/bin/activate
## pip install boto3
## freeze dependency packages
## pip freeze > requirements.txt

# install dependent packages
## pip install -r requirements.txt

cd source

python backend/init_eks.py
