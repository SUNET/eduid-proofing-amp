import os

from setuptools import setup, find_packages


here = os.path.abspath(os.path.dirname(__file__))
README = open(os.path.join(here, 'README.md')).read()
CHANGES = open(os.path.join(here, 'CHANGES.md')).read()
install_requires = open("requirements/common.txt").readlines()
tests_require = open("requirements/testing.txt").readlines()

version = '0.0.1b0'

setup(name='eduid-proofing-amp',
      version=version,
      description='eduID Proofing Attribute Manager Plugin',
      long_description=README + '\n\n' + CHANGES,
      classifiers=[
          # Get strings from http://pypi.python.org/pypi?%3Aaction=list_classifiers
          'License :: OSI Approved :: BSD License',
      ],
      keywords='',
      author='NORDUnet A/S',
      url='https://github.com/SUNET/eduid-proofing-amp',
      license='BSD',
      packages=find_packages(),
      include_package_data=True,
      zip_safe=False,
      install_requires=install_requires,
      tests_require=tests_require,
      extras_require={
            'testing': tests_require,
      },
      test_suite='eduid_proofing_amp',
      entry_points="""
      [eduid_am.attribute_fetcher]
      eduid_oidc_proofing = eduid_proofing_amp:attribute_fetcher
      eduid_letter_proofing = eduid_proofing_amp:attribute_fetcher

      [eduid_am.plugin_init]
      eduid_oidc_proofing = eduid_proofing_amp:oidc_plugin_init
      eduid_letter_proofing = eduid_proofing_amp:letter_plugin_init
      """,
      )
