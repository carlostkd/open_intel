"""
crawler — Phase 1C recursive .onion spider.

Public interface:
    CrawlResult  dataclass  — crawl statistics + scraped content
    crawl()      async fn   — entry point; accepts seeds, query, and tuning params

Example
-------
    import asyncio
    from crawler import CrawlResult, crawl

    result: CrawlResult = asyncio.run(crawl(
        seed_urls=["http://exampleonionaddressv3aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.onion"],
        query="ransomware affiliate recruitment",
        max_depth=2,
        max_pages=50,
        min_relevance=0.3,
    ))

    print(result.pages_crawled, result.new_urls_discovered)
    for page in result.results:
        print(page["url"], page["content"][:200])
"""

from crawler.spider import CrawlResult, crawl

__all__ = ["CrawlResult", "crawl"]
