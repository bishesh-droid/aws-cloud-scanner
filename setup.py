from setuptools import setup, find_packages

setup(
    name='aws-scanner',
    version='0.1.0',
    packages=find_packages(),
    include_package_data=True,
    install_requires=[
        'click',
        'boto3',
    ],
    entry_points={
        'console_scripts': [
            'aws-scanner = aws_scanner.cli:scan',
        ],
    },
)
