provider "aws" {
  profile = "digio-onetrust"
  region = "sa-east-1"
}

provider "aws" {
  alias = "digio-onetrust"
  profile = "digio-onetrust"
  region = "sa-east-1"
}

provider "aws" {
  alias = "infra"
  profile = "digio-infrashared"
  region = "sa-east-1"
}

terraform {
  backend "s3" {
    bucket     = "tf-state-onetrust"
    key        = "ops_data_discovery_core.tfstate"
    region     = "sa-east-1"
    profile    = "digio-onetrust"
  }
}

