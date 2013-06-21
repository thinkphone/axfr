import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.Scanner;
import java.util.TreeMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.logging.Logger;

import org.xbill.DNS.DClass;
import org.xbill.DNS.Message;
import org.xbill.DNS.Name;
import org.xbill.DNS.Rcode;
import org.xbill.DNS.Record;
import org.xbill.DNS.Section;
import org.xbill.DNS.SimpleResolver;
import org.xbill.DNS.Type;

/**
 * @author gf<gf@gfzj.us>
 * @see DNS域传送信息泄露：http://drops.wooyun.org/papers/64
 *      最近频繁曝出很多大网站dns域传送漏洞，于是写了一个脚本检测alexa top100W的网站。
 *      网站列表，可以在http://s3.amazonaws.com/alexa-static/top-1m.csv.zip
 *      下载，然后解压出top-1m.csv 本程序用到了http://www.xbill.org/dnsjava/ 请自己下载jar包
 * @usage 编译:javac -cp org.xbill.dns_2.1.5.jar TransferCheck.java <br>
 *        运行:<br>
 *        两个参数:TransferCheck top-1m.csv位置 线程个数.比如<br>
 *        Linux/Mac java -cp org.xbill.dns_2.1.5.jar:. TransferCheck top-1m.csv
 *        200<br>
 *        windows java -cp org.xbill.dns_2.1.5.jar;. TransferCheck top-1m.csv
 *        200
 * @result 经过粗略去重复，top100W中找到域名987681个(包括二级域名)。可以dns传送的域名有98046个，约占9.926%.
 *         考虑到我用的是默认的上海电信的dns，而且同时200个线程，会导致有的域名在得到ns的时候，超时出错。再加上二级域名。正常应该在10%+。
 *         欢迎把程序放到国外主机上测试。
 * 
 */
public class TransferCheck {

	String listFile = "/ramdisk/top-1m.csv";
	int threadCount = 200;
	SimpleResolver res;
	static Logger log = Logger.getLogger(Class.class.getName());

	public TransferCheck() {
		super();
		try {
			// 结果缓存文件夹。
			File dir = new File("axfr.result");
			if (!dir.exists())
				dir.mkdir();

			// 初始化默认resov
			res = new SimpleResolver();
			// 线程过多，容易timeout
			res.setTimeout(30);
		} catch (Exception e) {
			e.printStackTrace();
		}
	}

	private void justDoIT() {
		try {
			// 读取缓存列表。
			HashSet<String> caches = new HashSet<>();
			if (new File(listFile + ".cache").exists()) {
				Scanner scan = new Scanner(new File(listFile + ".cache"));
				while (scan.hasNextLine()) {
					String line = scan.nextLine();
					caches.add(line);
				}
				scan.close();
			}
			// 读取域名列表。格式在http://s3.amazonaws.com/alexa-static/top-1m.csv.zip
			HashSet<String> list = new HashSet<>();
			Scanner scan = new Scanner(new File(listFile));
			while (scan.hasNextLine()) {
				String line = scan.nextLine().trim();
				line = line.substring(1 + line.indexOf(','));
				int pathIndex = line.indexOf('/');
				if (pathIndex > 0)
					line = line.substring(0, pathIndex);
				if (!caches.contains(line))
					list.add(line);
			}
			scan.close();
			check(list);
		} catch (Exception e) {
			e.printStackTrace();
		}
	}

	private LinkedList<String> getNS(String domain) {
		LinkedList<String> ret = new LinkedList<String>();
		try {
			Record rec = Record.newRecord(Name.fromString(domain, Name.root),
					Type.NS, DClass.IN);
			Message query = Message.newQuery(rec);
			Message response = res.send(query);
			Record[] r = response.getSectionArray(Section.ANSWER);
			for (Record record : r) {
				String strRec = record.rdataToString();
				ret.add(strRec.substring(0, strRec.length() - 1));
			}
		} catch (Exception e) {
			log.warning("error get NS for " + domain + "\t" + e.getMessage());
		}
		return ret;
	}

	private String doAXFR(String ns, String domain) {
		String ret = null;
		try {
			SimpleResolver resv = new SimpleResolver(ns);
			Record rec = Record.newRecord(Name.fromString(domain, Name.root),
					Type.AXFR, DClass.IN);
			Message query = Message.newQuery(rec);
			Message response = resv.send(query);
			if (response.getRcode() == Rcode.NOERROR)
				ret = response.toString();
		} catch (Exception e) {
			if (count % 200 == 0)
				log.warning("AXFR error:" + domain + "\t"
						+ e.getLocalizedMessage());
		}
		return ret;
	}

	int count = 0;
	int total = 0;
	StringBuilder sb = new StringBuilder();

	private synchronized void cache(String domain) {
		sb.append(domain).append("\n");
		if (count++ % 100 == 0) {
			try {
				Files.write(Paths.get(listFile + ".cache"), sb.toString()
						.getBytes(), StandardOpenOption.CREATE,
						StandardOpenOption.APPEND);
				sb = new StringBuilder();
				log.info(String.format("%d/%d", count, total));
			} catch (IOException e) {
				e.printStackTrace();
			}
		}
	}

	private void check(HashSet<String> domains) {
		total = domains.size();
		log.info("发现域名个数：" + total);
		ExecutorService service = Executors.newFixedThreadPool(threadCount);
		for (final String domain : domains) {
			service.execute(new Runnable() {

				@Override
				public void run() {
					try {
						LinkedList<String> ns = getNS(domain);
						for (String nameserver : ns) {
							String ret = doAXFR(nameserver, domain);
							if (ret != null) {
								Files.write(
										Paths.get("axfr.result"
												+ File.separator + domain + "@"
												+ nameserver),
										ret.getBytes("UTF-8"));

								break;
							}
						}
						cache(domain);
					} catch (Exception e) {
						e.printStackTrace();
					}
				}
			});
		}
		service.shutdown();
		try {
			service.awaitTermination(30, TimeUnit.DAYS);
		} catch (InterruptedException e) {
			e.printStackTrace();
		}
		service.shutdownNow();
	}

	private void report() {
		try {
			HashMap<String, Integer> all = new HashMap<>();
			Scanner scan = new Scanner(new File(listFile));
			while (scan.hasNextLine()) {
				String line = scan.nextLine().trim();
				int rank = Integer
						.parseInt(line.substring(0, line.indexOf(',')));

				line = line.substring(1 + line.indexOf(','));
				int pathIndex = line.indexOf('/');
				if (pathIndex > 0)
					line = line.substring(0, pathIndex);

				all.put(line, rank);
			}
			scan.close();
			HashMap<Integer, String> res = new HashMap<>();
			for (String file : new File("axfr.result").list()) {
				res.put(all.get(file.substring(0, file.indexOf('@'))), file);
			}
			TreeMap<Integer, String> tm = new TreeMap<>(res);
			System.out.println("alexa排名	域名");
			for (Integer k : tm.keySet()) {
				System.out.println(k + "\t" + tm.get(k));
			}
		} catch (NumberFormatException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (FileNotFoundException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}

	public static void main(String[] args) {
		TransferCheck tc = new TransferCheck();
		if (args.length < 2) {
			System.out
					.println("usage:\n\tjava -cp org.xbill.dns_2.1.5.jar:. TransferCheck top-1m.csv 200");
			System.exit(0);
		}
		tc.listFile = args[0];
		tc.threadCount = Integer.parseInt(args[1]);

		tc.justDoIT();
		tc.report();
	}

}
