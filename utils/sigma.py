
from .reternalapi import ReternalAPI
import glob
import yaml
import asyncio
import copy
import re

TECHNIQUE_PATTERN = 't\d{4}(\.\d{2})?'
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
    def __init__(self, config_files = None):
        self.config_files = config_files if config_files else []


    @staticmethod
    def find_technique(content):
        all_techniques = []
        for technique in content:
            search_technique = re.search(TECHNIQUE_PATTERN, technique)
            if search_technique:
                all_techniques.append(search_technique.group().upper())
        return all_techniques

    @property
    def rules(self):
        for config in self.config_files:
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
                        rule_data = {
                            'external_id': merged_rule['id'],
                            'title': merged_rule['title'],
                            'platform': 'sigma',
                            'techniques': Sigma.find_technique(merged_rule.get('tags', [])),
                            'tags': merged_rule['tags'],
                            'description': merged_rule['description'],
                            'categories': categories,
                            'content': merged_rule
                        }
                        yield rule_data

                elif len(yaml_objects) == 1:
                    yaml_objects[0]['categories'] = categories
                    yaml_objects[0]['sigma_id'] = yaml_objects[0]['id']
                    rule_data = {
                        'external_id': yaml_objects[0]['id'],
                        'title': yaml_objects[0]['title'],
                        'platform': 'sigma',
                        'techniques': Sigma.find_technique(yaml_objects[0].get('tags', [])),
                        'tags': yaml_objects[0].get('tags', []),
                        'description': yaml_objects[0]['description'],
                        'categories': categories,
                        'content': yaml_objects[0]
                    }

                    yield rule_data

    @classmethod
    def from_path(cls, path = '../sigma/rules'):
        config_files = glob.iglob(f'{path}/**/**/*.yml', recursive=True)
        return cls(config_files=config_files)

async def import_sigma(*args, **kwargs):
    ''' Load all config files and import mapped techniques '''
    sigma = Sigma.from_path(kwargs['path'])
    async with ReternalAPI(kwargs['api_url']) as reternal:
        for rule in sigma.rules:
            await reternal.save('/rules/sigma', rule)


if __name__ == "__main__":
    asyncio.run(import_sigma())

