'''Setup the project'''

from setuptools import setup, find_packages

setup(
    name='my_shell',
    version='0.1.0',
    setup_requires=['pytest-runner', 'pytest-pylint'],
    tests_require=['pytest', 'pylint'],
    packages=find_packages(include=['myshell']),
    test_suite = 'test',
    install_requires=[
        "colorama >= 0.4.0"
    ],
    python_requires='>=3.9'
)
