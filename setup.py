
import os
import setuptools

def readme():
    path = os.path.dirname(__file__)
    with open(os.path.join(path, 'README.rst')) as f:
        return f.read()

name = 'flask-csp'
description = 'A Flask extension/decorator to easily add Content-Security-Policy (CSP) headers'
version = '1.0.2'
author = 'Fictive Kin LLC'
email = 'hello@fictivekin.com'
classifiers = [
    'Development Status :: 4 - Beta',
    'Environment :: Web Environment',
    'Intended Audience :: Developers',
    'License :: OSI Approved :: MIT License',
    'Programming Language :: Python',
    'Programming Language :: Python :: 3.6',
    'Programming Language :: Python :: 3.7',
    'Programming Language :: Python :: 3.8',
    'Programming Language :: Python :: 3.9',
    'Programming Language :: Python :: 3.10',
    'Programming Language :: Python :: 3.11',
    'Programming Language :: Python :: 3.12',
    'Programming Language :: Python :: 3.13',
    'Operating System :: OS Independent',
    'Topic :: Internet :: WWW/HTTP :: Dynamic Content',
    'Topic :: Software Development',
    'Topic :: Software Development :: Libraries :: Python Modules'
]

if __name__ == "__main__":
    setuptools.setup(
        name=name,
        version=version,
        description=description,
        long_description=readme(),
        classifiers=classifiers,
        url='https://github.com/fictivekin/flask-csp',
        author=author,
        author_email=email,
        maintainer=author,
        maintainer_email=email,
        license='MIT',
        python_requires=">=3.6",
        packages=setuptools.find_packages(),
        install_requires=[
            'Flask',
        ],
        extras_require={
            'tests': [
                'pytest',
                'pytest-cov',
                'pytest-randomly',
            ],
            'lint': [
                'pylint',
            ],
        },
    )
