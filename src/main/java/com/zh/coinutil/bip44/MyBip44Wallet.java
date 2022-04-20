package com.zh.coinutil.bip44;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.web3j.crypto.Bip32ECKeyPair;
import org.web3j.crypto.Credentials;
import org.web3j.crypto.Hash;
import org.web3j.crypto.MnemonicUtils;
import org.web3j.utils.Numeric;

import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;

/*
BIP44则是为这个路径约定了一个规范的含义(也扩展了对多币种的支持)，BIP0044指定了包含5个预定义树状层级的结构：
m / purpose' / coin' / account' / change / address_index
  m是固定的, Purpose也是固定的，值为44（或者 0x8000002C）
  Coin type
  这个代表的是币种，0代表比特币，1代表比特币测试链，60代表以太坊
  完整的币种列表地址：https://github.com/satoshilabs/slips/blob/master/slip-0044.md
  Account
  代表这个币的账户索引，从0开始
  Change
  常量0用于外部(收款地址)，常量1用于内部（也称为找零地址）。外部用于在钱包外可见的地址（例如，用于接收付款）。内部链用于在钱包外部不可见的地址，用于返回交易变更。 (所以一般使用0)
      非比特币地址都是0
  address_index
  这就是地址索引，从0开始，代表生成第几个地址，官方建议，每个account下的address_index不要超过20

//  根据 EIP85提议的讨论以太坊钱包也遵循BIP44标准，确定路径是m/44'/60'/a'/0/n
        a 表示帐号，n 是第 n 生成的地址，60 是在 SLIP44 提案中确定的以太坊的编码

    第一个账号就是 m/44'/60'/0/0/0,第二个是 m/44'/60'/0/0/1
 */

/**
 * 因为 Bip44WalletUtils generateBip44Wallet 生成的钱包,在用 loadBip44Credentials 助记词加载后的地址不一致,
 * 所以自己包装一个 bip44 的钱包
 * 此钱包的 mainAddr一般是第一个子地址
 * 只要有助记词,可以推导出所有子钱包
 * 非en助记词都是基于en的,没有直接加载en助记词
 */
public class MyBip44Wallet {
  public final static String Local_En = "en";

  private static final ObjectMapper objectMapper = new ObjectMapper();

  private static final String savePre = "mybip44wallet_";
  public static final int HARDENED_BIT = 0x80000000;
  public static final int PURPOSE = 44 | HARDENED_BIT;
  public static final int COIN_TYPE_ETH = 60;
  public static final int COIN_TYPE_BTC = 0;

  private String filePath;
  private String fileName;
  private String mnemonic;
  private String mnemonicEn;
  private String password;
  private String local = Local_En;

  private Bip32ECKeyPair masterKeypair; //Bip32ECKeyPair 根 key,不对外展示的

  private String mainAddr;  //主地址 第0个账号的第0个地址
  private String mainPk;  //主私钥   第0个账号的第0个地址 对应的私钥

  private Map<String, String> addrs = new HashMap<>();
  private Map<String, String> pks = new HashMap<>();
  private Map<String, Credentials> credentials = new HashMap<>();

  /**
   * 根据密码和助记词生成钱包
   * 通过助记词可以推导出主私钥,不能反向推出
   *
   * @param password
   * @param mnemonic
   */
  private MyBip44Wallet(String password, String mnemonic) {
    this(password, mnemonic, Local_En);
  }

  private MyBip44Wallet(String password, String mnemonic, String local) {
    this.password = password == null ? "" : password;
    this.mnemonic = mnemonic;
    this.local = local;
    if (Local_En.equals(local)) {
      this.mnemonicEn = mnemonic;
    } else {
      this.mnemonicEn = MnemUtils.localMnemToEn(mnemonic, this.local);
    }
    init();
  }

  /**
   * 根据密码和助记词生成钱包实例
   *
   * @param pwd
   * @param mnemonic
   * @return
   */
  public static MyBip44Wallet createWalletFromMnemonic(String pwd, String mnemonic) {
    return createWalletFromMnemonic(pwd, mnemonic, Local_En);
  }

  public static MyBip44Wallet createWalletFromMnemonic(String pwd, String mnemonic, String local) {
    return new MyBip44Wallet(pwd, mnemonic, local);
  }

  /**
   * 以指定密码生成一个新钱包,并保存文件到指定路径
   *
   * @param pwd
   * @param filePath
   * @return
   */
  public static MyBip44Wallet createWallet(String pwd, String filePath) {
    return createWallet(pwd, filePath, Local_En);
  }

  public static MyBip44Wallet createWallet(String pwd, String filePath, String local) {
    try {
      MyBip44Wallet w = createWalletNoFile(pwd, local);
      w.saveTo(new File(filePath));
      w.filePath = filePath;
      return w;
    } catch (Exception e) {
      throw new RuntimeException(e);
    }
  }

  /**
   * 以指定密码生成一个新钱包,不保存文件,指定助记词长度
   *
   * @param pwd 密码
   * @param len 助记词长度,  12,15,18,21,24
   * @return
   */
  public static MyBip44Wallet createWalletNoFile(String pwd, int len) {
    int size = len / 3;
    if (size < 4 || size > 8) {
      throw new IllegalArgumentException("长度错误:" + len);
    }
    return createWalletNoFile0(pwd, size * 4);
  }

  /**
   * 以指定密码生成一个新钱包,不保存文件,助记词长度为 12
   *
   * @param pwd
   * @return
   */
  public static MyBip44Wallet createWalletNoFile(String pwd) {
    return createWalletNoFile0(pwd, 16);  //默认 生成 12 个助记词
  }

  public static MyBip44Wallet createWalletNoFile(String pwd, String local) {
    return createWalletNoFile0(pwd, 16, local);  //默认 生成 12 个助记词
  }

  private static MyBip44Wallet createWalletNoFile0(String pwd, int byteSize) {
    return createWalletNoFile0(pwd, byteSize, Local_En);
  }

  private static MyBip44Wallet createWalletNoFile0(String pwd, int byteSize, String local) {
    byte[] initialEntropy = new byte[byteSize];   //长度 除以 4 ,为4,5,6,7,8 ,助记词长度为 12、15、18、21、24
    SecureRandomUtils.secureRandom().nextBytes(initialEntropy);
    String mnemonic = MnemonicUtils.generateMnemonic(initialEntropy);
    if (!Local_En.equals(local)) {
      mnemonic = MnemUtils.enMnemToLocal(mnemonic, local);
    }
    return new MyBip44Wallet(pwd, mnemonic, local);
  }

  private void init() {
    byte[] seed = MnemonicUtils.generateSeed(mnemonicEn, password);
    this.masterKeypair = Bip32ECKeyPair.generateKeyPair(seed);
//    Credentials c = Credentials.create(this.masterKeypair);
//    this.mainAddr = c.getAddress();
//    this.mainPk = Numeric.toHexStringNoPrefix(c.getEcKeyPair().getPrivateKey());

//    mainAddr 默认为 eth ,用第一个账户的第一个子账号,根key不对外
    this.mainAddr = this.getAddr(0);
    this.mainPk = this.getPk(0);
  }

  public static MyBip44Wallet loadFromFile(String pwd, File file) {
    try {
      byte[] bs = objectMapper.readValue(file, byte[].class);
      bs = xor(bs, pwd);
      String mnem = new String(bs, StandardCharsets.UTF_8);
      String pre = savePre + pwd + "_";
      if (mnem.startsWith(pre)) {
        String tmp = mnem.substring(pre.length());
        int idx = tmp.lastIndexOf("_");
        String tmpLocal = tmp.substring(0, idx);
        String tmpMnem = tmp.substring(idx + 1);

        MyBip44Wallet rtn = new MyBip44Wallet(pwd, tmpMnem, tmpLocal);
        rtn.fileName = file.getName();
        rtn.filePath = file.getParent();
        return rtn;
      } else {
        throw new IllegalArgumentException("密码错误");
      }
    } catch (IOException e) {
      throw new RuntimeException(e);
    }
  }

  public void saveTo(File dir) {
    String fileName = Numeric.cleanHexPrefix(this.getMainAddr()) + ".bip44";
    File file = new File(dir, fileName);
    if (this.filePath == null) {
      this.filePath = dir.getAbsolutePath();
    }
    this.fileName = fileName;
    try {
      byte[] bs = (savePre + password + "_" + local + "_" + this.getMnemonic()).getBytes(StandardCharsets.UTF_8);
      bs = xor(bs, this.password);
      objectMapper.writeValue(file, bs);
    } catch (Exception e) {
      throw new RuntimeException(e);
    }
  }

  private static byte[] xor(byte[] data, String password) {
    byte[] hash = Hash.sha3(password.getBytes(StandardCharsets.UTF_8));
    int len = Math.min(data.length, hash.length);
    int allLen = data.length;
    byte[] rtn = new byte[allLen];
    for (int i = 0; i < allLen; i++) {
      if (i < len) {
        rtn[i] = (byte) (data[i] ^ hash[i]);
      } else {
        rtn[i] = data[i];
      }
    }
    return rtn;
  }

  private static Bip32ECKeyPair generateBip44KeyPairEth(Bip32ECKeyPair master, int account, int index) {
    return generateBip44KeyPair(master, COIN_TYPE_ETH, account, index);
  }

  private static Bip32ECKeyPair generateBip44KeyPair(Bip32ECKeyPair master, int coinType, int account, int index) {
    // m/44'/60'/0'/0/0
//    final int[] path = {PURPOSE, COIN_ETH, account | HARDENED_BIT, index};
    final int[] path = {PURPOSE, coinType | HARDENED_BIT, account | HARDENED_BIT, 0, index};
    return Bip32ECKeyPair.deriveKeyPair(master, path);
  }

  private static Bip32ECKeyPair generateBip44KeyPairEth(Bip32ECKeyPair parent, int[] path) {
    return Bip32ECKeyPair.deriveKeyPair(parent, path);
  }

  private String getKey(int coinType, int account, int index) {
    return "m/44'/" + coinType + "'/" + account + "'/0/" + index;
  }

  private Credentials createCredentials(int coinType, int account, int index) {
    Bip32ECKeyPair keyPair = generateBip44KeyPair(masterKeypair, coinType, account, index);
    return Credentials.create(keyPair);
  }

//  private Credentials createCredentials(int account, int index) {
//    Bip32ECKeyPair keyPair = generateBip44KeyPairEth(masterKeypair, account, index);
//    return Credentials.create(keyPair);
//  }

  /**
   * 取以太坊第0个账号的指定索引账户的证书
   *
   * @param index 地址索引
   * @return
   */
  public Credentials getCredentials(int index) {
    return getCredentials(COIN_TYPE_ETH, 0, index);
  }

  /**
   * 取指定类型外部子账户的证书,包括地址,pk等
   *
   * @param coinType 币种类型
   * @param account  账户索引
   * @param index    地址索引
   * @return
   */
  public Credentials getCredentials(int coinType, int account, int index) {
    String key = getKey(coinType, account, index);
    Credentials rtn = credentials.get(key);
    if (rtn == null) {
      rtn = createCredentials(coinType, account, index);
      credentials.put(key, rtn);
    }
    return rtn;
  }

  /**
   * 取以太坊第0个账户的指定索引的地址
   *
   * @param index 地址索引
   * @return
   */
  public String getAddr(int index) {
    return getAddr(COIN_TYPE_ETH, 0, index);
  }

  /**
   * 取指定类型外部子账户的地址
   *
   * @param coinType 币种类型
   * @param account  账户索引
   * @param index    地址索引
   * @return
   */
  public String getAddr(int coinType, int account, int index) {
    String key = getKey(coinType, account, index);
    String rtn = addrs.get(key);
    if (rtn == null) {
      rtn = getCredentials(coinType, account, index).getAddress();
      addrs.put(key, rtn);
    }
    return rtn;
  }

  /**
   * 取以太坊第0个账户的指定索引的私钥
   *
   * @param index 地址索引
   * @return
   */
  public String getPk(int index) {
    return getPk(COIN_TYPE_ETH, 0, index);
  }

  /**
   * 取指定类型外部子账户的私钥
   *
   * @param coinType 币种类型
   * @param account  账户索引
   * @param index    地址索引
   * @return
   */
  public String getPk(int coinType, int account, int index) {
    String key = getKey(coinType, account, index);
    String rtn = pks.get(key);
    if (rtn == null) {
      rtn = Numeric.toHexStringNoPrefix(getCredentials(coinType, account, index).getEcKeyPair().getPrivateKey());
      pks.put(key, rtn);
    }
    return rtn;
  }

  private int[] getPathIntArray(String path) {
    String tPath = path.replace("m/", "").replace("'/", "/").replace("44/", "");
    String[] ss = tPath.split("/");
    if (ss.length != 4) {
      throw new IllegalArgumentException("path错误:" + path);
    }
    if (!"0".equals(ss[2])) {
      throw new IllegalArgumentException("只支持对外钱包地址:" + path);
    }
    int[] rtn = new int[ss.length];
    for (int i = 0; i < ss.length; i++) {
      rtn[i] = Integer.parseInt(ss[i]);
    }
    return rtn;
  }

  /**
   * 取指定path对应的地址 16进制表示
   * 只支持外部地址,即倒数第二位是0
   * path 如: m/44'/60'/0/0/0
   *
   * @param path
   * @return
   */
  public String getAddrByPath(String path) {
    int[] paths = getPathIntArray(path);
    return getAddr(paths[0], paths[1], paths[3]);
  }

  /**
   * 取指定path对应的私钥16进制表示
   * 只支持外部地址,即倒数第二位是0
   * path 如: m/44'/60'/0/0/0
   *
   * @param path
   * @return
   */
  public String getPkByPath(String path) {
    int[] paths = getPathIntArray(path);
    return getPk(paths[0], paths[1], paths[3]);
  }

  public String getFilePath() {
    return filePath;
  }

  public String getFileName() {
    return fileName;
  }

  public String getMnemonic() {
    return mnemonic;
  }

  public String getMainAddr() {
    return mainAddr;
  }

  public String getMainPk() {
    return mainPk;
  }
}
