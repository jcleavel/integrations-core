from typing import Tuple, Union
from urllib.parse import ParseResult, urlencode, urlunparse

import botocore.session
import redis
from botocore.model import ServiceId
from botocore.signers import RequestSigner
from botocore.awsrequest import prepare_request_dict
from botocore.useragent import UserAgentString
from cachetools import TTLCache, cached

class ElastiCacheIAMProvider(redis.CredentialProvider):
    """
    This class implements the redis library's CredentialProvider type.

    It manages the AWS client sessions and generates the request signatures required to authenticate
    with AWS Elasticache instances.

    # This implementation was adapted from the example in the Redis library's documentation.
    """

    def __init__(self, username, cache_name, region="us-west-2", role_arn=None):
        self.username = username
        self.cache_name = cache_name
        self.region = region

        session = botocore.session.get_session()
        if role_arn:
            # when role_arn is defined, assume the role to generate the token
            # this can be used for cross-account access
            sts_client = session.create_client("sts")
            assumed_role = sts_client.assume_role(RoleArn=role_arn, RoleSessionName="datadog-elasticache-iam-auth-session")
            credentials = assumed_role["Credentials"]
            session.set_credentials(
                access_key=credentials["AccessKeyId"],
                secret_key=credentials["SecretAccessKey"],
                token=credentials["SessionToken"],
            )
        session.set_config_variable('region', region)

        self.user_agent = session.user_agent
        self.request_signer = RequestSigner(
            ServiceId("elasticache"),
            self.region,
            "elasticache",
            "v4",
            session.get_credentials(),
            session.get_component("event_emitter"),
        )

    # Generated IAM tokens are valid for 15 minutes
    @cached(cache=TTLCache(maxsize=128, ttl=900))
    def get_credentials(self) -> Union[Tuple[str], Tuple[str, str]]:
        request_dict = {
            'url_path': '/',
            'query_string': {"Action": "connect", "User": self.username},
            'headers': {},
            'body': {},
            'method': 'GET',
        }
        prepare_request_dict(request_dict, "https://" + self.cache_name, user_agent=self.user_agent)

        signed_url = self.request_signer.generate_presigned_url(
            request_dict,
            operation_name="connect",
            expires_in=900,
            region_name=self.region,
        )
        # RequestSigner only seems to work if the URL has a protocol, but
        # Elasticache only accepts the URL without a protocol
        # So strip it off the signed URL before returning
        return (self.username, signed_url.removeprefix("https://"))
