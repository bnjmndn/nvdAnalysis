# nvdAnalysis - exploring the National Vulnerability Database for severity of vulns
## Introduction
This workbook analyzes data from the [National Vulnerability Database (NVD)](https://nvd.nist.gov), which is the U.S. government repository of standards based vulnerability management data represented using the Security Content Automation Protocol (SCAP). The NVD includes databases of security checklist references, security-related software flaws, misconfigurations, product names, and impact metrics.

## Data
The dataset has been converted from JSON to CSV format to allow for easier analysis in R. The original JSON or XML formats are available [here](https://nvd.nist.gov/vuln/data-feeds).

## Goals and variables explored
This work is part of an ongoing project with the [Center for Democracy and Technology](www.cdt.org), which explores the concept of 'digital defects'. 

In the NVD database, the [Common Vulnerability Scoring System (CVSS)](https://www.first.org/cvss/user-guide) is used to score the impact and severity of each vulnerability. By exploring the NVD and examining the distribution of severity and impact of the known vulnerabilities we are able to better inform efforts to apply the legal concept of 'defects' to these technologies. While it may be true that it is 'difficult to write bug free code' or that 'not all bugs can be known ahead of time', that does not mean that there are known critical vulnerabilities that should be fixed before these technologies are shipped. Identifying the frequency of these vulnerabiltiies appearing in software helps us identify and determine a severity threshold at which a vulnerability might render a product as 'defective' (and thus subject to strict products liability claims). 

## Outputs
- [pdf output](https://github.com/bnjmndn/nvdAnalysis/blob/master/Analysing%20the%20NVD%20database%20to%20understand%20the%20distribution%20of%20severity%20of%20vulnerabilities.pdf)
- [html output](https://github.com/bnjmndn/nvdAnalysis/blob/master/Analysing%20the%20NVD%20database%20to%20understand%20the%20distribution%20of%20severity%20of%20vulnerabilities.html)

## Dependent packages
- [jsonlite](https://cran.r-project.org/web/packages/jsonlite/)
- [ggplot2](https://cran.r-project.org/web/packages/ggplot2/)
- [dplyr](https://cran.r-project.org/web/packages/dplyr/)
- [tidyverse](https://cran.r-project.org/web/packages/tidyverse/)
- [grid](https://cran.r-project.org/src/contrib/Archive/grid/)
- [plyr](https://cran.r-project.org/web/packages/plyr/)
- [psych](https://cran.r-project.org/web/packages/psych/)
