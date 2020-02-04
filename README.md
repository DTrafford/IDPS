install python 3 and pip 3

then in the main folder /

<!-- npm install

then to run react
npm run start

then in another terminal, -->

python -m venv idpsenv // creating venv
source idpsenv/bin/activate
pip install pip-tools
pip install -r requirements.txt && pip install -r dev-requirements.txt

cd backend
cp .env.example .env
python manage.py makemigrations
python manage.py migrate

then to run python
source idpsenv/bin/activate
python3 manage.py runserver

then in another terminal,
brew install redis

then run redis
redis-server
