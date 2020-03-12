install python 3 and pip 3

then in the main folder /

<!-- npm install

then to run react
npm run start

then in another terminal, -->

python -m venv idpsenv // creating venv
source idpsenv/bin/activate

pip install pip-tools
idpsenv\Scripts\activate.bat -- art
pip install -r requirements.txt && pip install -r dev-requirements.txt
pip3 install -r requirements.txt && pip3 install -r dev-requirements.txt --art

pip install -r requirements.txt --upgrade

cd backend
cp .env.example .env
copy .env.example .env --art
python manage.py makemigrations
python manage.py migrate

then to run python
source idpsenv/bin/activate
python3 manage.py runserver

then in another terminal,
brew install redis

then run redis
redis-server

redis-cli ping --art


Win10 PowerShell
    Set WinPolicy
	    python -V
	    pip freeze
	    Set-ExecutionPolicy Unrestricted
	
	Install Virtual Env
	    goto Project Directory - X:\CyberSecurity\CBER710-Capsone Project\Capstone Project\IDPS\backend
	    mkdir venvArt           - virtualenv parent directory
	    cd venvArt
	    pip install virtualenv
        pip freeze
        virtualenv .            - create virtualenv
        virtualenv -p python3 . - if you have other versions of python
        ./Scripts/activate
    Install Django
        pip instal django
        mkdir src
        ==MIGRATION
            cd src              - PowerShell
            python manage.py makemigrations
            python manage.py migrate
        django-admin.py startproject venvArtSrc .
        python manage.py runserver
        
    

