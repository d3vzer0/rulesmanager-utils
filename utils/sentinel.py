
from .reternalapi import ReternalAPI
import glob
import yaml
import asyncio


class Sentinel:
    def __init__(self, config_files = None):
        self.config_files = config_files if config_files else []

    @property
    def rules(self):
        for config in self.config_files:
            with open(config) as yamlfile:
                yaml_object = yaml.load(yamlfile, Loader=yaml.FullLoader)
                rule_data = {
                    'external_id': yaml_object['id'],
                    'title': yaml_object['name'],
                    'description': yaml_object['description'],
                    'content': yaml_object,
                    'platform': 'sentinel'
                }
                if 'relevantTechniques' in yaml_object and yaml_object['relevantTechniques']:
                    rule_data['techniques'] = yaml_object['relevantTechniques']
                yield rule_data


    @classmethod
    def from_path(cls, path = '../Azure-Sentinel/Detections'):
        config_files = glob.iglob(f'{path}/**/**/*.yaml', recursive=True)
        return cls(config_files)


async def import_sentinel(*args, **kwargs):
    ''' Load sentinel config files and create entry via API '''
    sigma = Sentinel.from_path(kwargs['path'])
    async with ReternalAPI(kwargs['api_url']) as reternal:
        for rule in sigma.rules:
            await reternal.save('/rules/sentinel', rule)


if __name__ == "__main__":
    asyncio.run(import_sentinel())

