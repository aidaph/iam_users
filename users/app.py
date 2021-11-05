#!/usr/bin/env python

import argparse
import logging
import os
import pprint
import sys

import oauthlib.oauth2
import requests.auth
import requests_oauthlib

from cliff.app import App
from cliff.command import Command
from cliff.commandmanager import CommandManager
from cliff.show import ShowOne
from cliff.lister import Lister

log = logging.getLogger('oauthlib')
log.addHandler(logging.StreamHandler(sys.stdout))
log.setLevel(logging.DEBUG)


def main(argv=sys.argv[1:]):

    app = App(
            description="Get Deep users from Mesos",
            version="0.1",
            command_manager=CommandManager("userscli.cli"),
            deferred_help=True,
        )
    return app.run(argv)


if __name__ == "__main__":
    sys.exit(main())


class Select(Lister):
    """A command with several structured item as a result."""

    def get_parser(self, prog_name):
         """Command argument parsing"""
         parser = super(Select, self).get_parser(prog_name)
         #group = self.formatter_group

         parser.add_argument(
              '--client-id', '-c',
              help="Oauth2 Client ID.",
              required=True,
              dest="client_id",
              )
         parser.add_argument(
              '--client-secret','-s',
              help="Oauth2 Client Secret.",
              required=True,
              dest="client_secret",
              )
         parser.add_argument(
              '--iam-url','-i',
              help="IAM base URL (e.g. "
                   "https://iam.deep-hybrid-datacloud.eu).",
              required=True,
              dest="iam_url",
              )

         return parser

    def take_action(self, parsed_args):
        """Command action."""
        scim_url = f"{parsed_args.iam_url}/scim/Users/"
        token_url = f"{parsed_args.iam_url}/token"

        client_id = parsed_args.client_id
        client_secret = parsed_args.client_secret
        

        auth = requests.auth.HTTPBasicAuth(client_id, client_secret)
        client = oauthlib.oauth2.BackendApplicationClient(client_id=client_id)
        oauth = requests_oauthlib.OAuth2Session(client=client)

        token = oauth.fetch_token(token_url=token_url, auth=auth)

        headers = {
            "Authentication": f'Bearer: {token["access_token"]}',
        }

        r = oauth.get("https://mesos.cloud.ifca.es/marathon/v2/apps",
              headers=headers)

        users = {}
        users_resumed = []
        apps = r.json()["apps"]
        for app in apps:
            user_id = app.get("labels", {}).get("created_by")

            if user_id:
                user_id, iam_instance = user_id.split("@")
                if iam_instance.rstrip("/") != parsed_args.iam_url.rstrip("/"):
                    continue

                # TODO(aloga): allow to get user info from different IAM instance
                r = requests.get(f"{scim_url}/{user_id}",
                         headers=headers)
                user = r.json()
            else:
                user = None
                iam_instance = None

            users.setdefault(iam_instance, {})
            users[iam_instance].setdefault(
                user_id,
                {   
                    "user_meta": user,
                    "deployments": [],
                }
            )
            users_resumed.append(user)


            app_meta = {
                "id": app.get("id"),
                "cpu": app.get("cpu"),
                "disk": app.get("disk"),
                "mem": app.get("mem"),
                "gpu": app.get("cpu"),
                "labels": app.get("labels"),
                "instances": app.get("instances"),
                "cmd": app.get("cmd"),
                "container": app.get("container"),
                "version": app.get("versionInfo"),
            }
            users[iam_instance][user_id]["deployments"].append(app_meta)
        
        #print(users_resumed[2]["name"]["formatted"])
        data = [
            users_resumed[2]["id"],
            users_resumed[2]["userName"],
            users_resumed[2]["name"]["formatted"],
            users_resumed[2]["emails"][0]["value"]
            ]
            
        columns = ["id", "username", "name", "email"]

        return (columns, data)