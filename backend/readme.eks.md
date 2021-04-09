
# python3 -m venv .env
## pip install boto3
## freeze dependency packages
## pip freeze > requirements.txt

# install dependent packages
## pip install -r requirements.txt

cd source
source .env/bin/activate
python backend/init_eks.py