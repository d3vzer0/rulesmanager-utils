
from .reternalapi import ReternalAPI
import glob
import yaml
import asyncio
import copy
import os

# Thanks fo Srisaila for this nested merge sample (https://stackoverflow.com/a/47564936)
# this example doesn't override nested dictionaries, which is the default behaviour of the
# regular dict update operation or {**dict1, **dict2}

def merge_dicts(default, override):    
    for key in override:
        if key in default:
            if isinstance(default[key], dict) and isinstance(override[key], dict):
                merge_dicts(default[key], override[key])
        else:
            default[key] = override[key]
    return default


class Sigma:
    def __init__(self, rules = None):
        self.rules = rules if rules else []

    @classmethod
    def from_path(cls, path = '../sigma/rules'):
        sigma_rules = []
        config_files = glob.iglob(f'{path}/**/**/*.yml', recursive=True)
        for config in config_files:
            split_path = config.split('/')
            categories = [split_path[-2], split_path[-3]]
            with open(config) as yamlfile:
                yaml_objects = list(yaml.load_all(yamlfile, Loader=yaml.FullLoader))
                if len(yaml_objects) > 1:
                    sigma_group = yaml_objects[0]
                    yaml_objects.pop(0)
                    for document in yaml_objects:
                        defaults = copy.deepcopy(sigma_group)
                        merged_rule = merge_dicts(defaults, document)
                        merged_rule['categories'] = categories
                        merged_rule['sigma_id'] = merged_rule['id']
                        sigma_rules.append(merged_rule)

                elif len(yaml_objects) == 1:
                    yaml_objects[0]['categories'] = categories
                    yaml_objects[0]['sigma_id'] = yaml_objects[0]['id']
                    sigma_rules.append(yaml_objects[0])

        return cls(sigma_rules)


async def import_sigma(*args, **kwargs):
    ''' Load all config files and import mapped techniques '''
    sigma = Sigma.from_path(kwargs['path'])
    async with ReternalAPI(kwargs['api_url']) as reternal:
        for rule in sigma.rules:
            await reternal.save('/sigmarules', rule)


if __name__ == "__main__":
    asyncio.run(import_sigma())

