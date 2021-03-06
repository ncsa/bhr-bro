from setuptools import setup

setup(name='bhr-bro',
    version='0.1.2',
    zip_safe=True,
    py_modules = ["bhr"],
    install_requires=[
        "bhr_client>=0.17",
        "dirq>=1.6.1",
    ],
    entry_points = {
        'console_scripts': [
            'bhr-bro = bhr:main',
        ]
    }
)
