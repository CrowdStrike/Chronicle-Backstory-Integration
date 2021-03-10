from setuptools import setup, find_packages

setup(
    name="chronicle-client",
    version="1.0",
    scripts=['src/chronicleclient.py'],
    install_requires=[
        'requests'
    ],
    entry_points={
    'console_scripts': [
        'chronicle-client=chronicleclient:main',
    ]
    }
)
