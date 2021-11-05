from setuptools import setup

PROJECT = "iam-users"

VERSION = "0.1"

setup(
    name=PROJECT,
    version=VERSION,
    description="Get IAM Mesos users running Deep Deployments",

    install_requires=['cliff'],

    entry_points={
        'console_scripts': [
            'userscli = users.app:main'
        ],
        'userscli.cli': [
            'select = users.app:Select',
        ],
    },
)
