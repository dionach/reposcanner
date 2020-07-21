FROM python:3

WORKDIR /usr/src/app
RUN pip install gitpython
COPY . .

ENTRYPOINT [ "python", "./reposcanner.py" ]
