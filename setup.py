from setuptools import setup

setup(name='bhr-bro',
    version='0.1.0',
    zip_safe=True,
    py_modules = ["bhr"],
    install_requires=[
        "bhr_client>=0.14",
        "dirq>=1.6.1",
    ],
    entry_points = {
        'console_scripts': [
            'bhr-bro = bhr:main',
        ]
    }
)
