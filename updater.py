from utils.attck import import_attck
from utils.products import import_products
from utils.sentinel import import_sentinel
from utils.sigma import import_sigma
import typer
import asyncio

app = typer.Typer()

@app.command()
def attck(api_url: str,
    cti_url: str = typer.Option('https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json'),
    magma_path: str = typer.Option('./context/magma_mapping.json')):
    typer.echo(f'Started import of ATTCK CTI')
    asyncio.run(import_attck(api_url=api_url, cti_url=cti_url, magma_path=magma_path))
    typer.echo(f'Finished import of ATTCK CTI')

# @app.command()
# def products(api_url: str, path: str = typer.Option('./mitre/datasource_mapping.json'),
#     access_token: str = typer.Option(..., prompt=True, hide_input=True, envvar="RT_TOKEN")):
#     typer.echo(f'Started import of products and datasource mapping')
#     asyncio.run(import_products(api_url=api_url, path=path, access_token=access_token))
#     typer.echo(f'Finished import of products and datasource mapping')

@app.command()
def sigma(api_url: str, path: str = typer.Option('../sigma/rules')):
    typer.echo(f'Started import of SIGMA rules')
    asyncio.run(import_sigma(api_url=api_url, path=path))
    typer.echo(f'Finished import of SIGMA rules')

@app.command()
def sentinel(api_url: str, path: str = typer.Option('../Azure-Sentinel/Detections')):
    typer.echo(f'Started import of Sentinel rules')
    asyncio.run(import_sentinel(api_url=api_url, path=path))
    typer.echo(f'Finished import of Sentinel rules')

# @app.command()
# def techniques(api_url: str, path: str = typer.Option('./mitre/techniques'),
#     access_token: str = typer.Option(..., prompt=True, hide_input=True, envvar="RT_TOKEN")):
#     typer.echo(f'Started import of mapped techniques rules')
#     asyncio.run(import_techniques(api_url=api_url, path=path, access_token=access_token))
#     typer.echo(f'Finished import of mapped techniques rules')

if __name__ == "__main__":
    app()