import os

from setuptools import setup, find_packages


here = os.path.abspath(os.path.dirname(__file__))
README = open(os.path.join(here, 'README.md')).read()
CHANGES = open(os.path.join(here, 'CHANGES.md')).read()

version = '0.1.2b0'

install_requires = [
        'eduid_am >= 0.6.0',
        'eduid_userdb >= 0.4.0b14',
]

tests_require = [
        'nose>=1.2.1',
        'nosexcover>=1.0.8',
        'coverage>=3.6',
]

setup(name='eduid-proofing-amp',
      version=version,
      description='eduID Proofing Attribute Manager Plugin',
      long_description=README + '\n\n' + CHANGES,
      classifiers=[
          # Get strings from http://pypi.python.org/pypi?%3Aaction=list_classifiers
          'License :: OSI Approved :: BSD License',
      ],
      keywords='',
      author='SUNET',
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
      eduid_lookup_mobile_proofing = eduid_proofing_amp:attribute_fetcher
      eduid_email = eduid_proofing_amp:attribute_fetcher
      eduid_phone = eduid_proofing_amp:attribute_fetcher
      eduid_personal_data = eduid_proofing_amp:attribute_fetcher
      eduid_security = eduid_proofing_amp:attribute_fetcher
      eduid_orcid = eduid_proofing_amp:attribute_fetcher
      eduid_eidas = eduid_proofing_amp:attribute_fetcher

      [eduid_am.plugin_init]
      eduid_oidc_proofing = eduid_proofing_amp:oidc_plugin_init
      eduid_letter_proofing = eduid_proofing_amp:letter_plugin_init
      eduid_lookup_mobile_proofing = eduid_proofing_amp:lookup_mobile_plugin_init
      eduid_email = eduid_proofing_amp:email_plugin_init
      eduid_phone = eduid_proofing_amp:phone_plugin_init
      eduid_personal_data = eduid_proofing_amp:personal_data_plugin_init
      eduid_security = eduid_proofing_amp:security_plugin_init
      eduid_orcid = eduid_proofing_amp:orcid_plugin_init
      eduid_eidas = eduid_proofing_amp:eidas_plugin_init
      """,
      )
