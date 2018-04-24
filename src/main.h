// Copyright (c) 2009 Satoshi Nakamoto
// Distributed under the MIT/X11 software license, see the accompanying
// file license.txt or http://www.opensource.org/licenses/mit-license.php.

class COutPoint;
class CInPoint;
class CDiskTxPos;
class CCoinBase;
class CTxIn;
class CTxOut;
class CTransaction;
class CBlock;
class CBlockIndex;
class CWalletTx;
class CKeyItem;

static const unsigned int MAX_SIZE = 0x02000000;
// COIN 表示的是一个比特币，而且100000000就是表示一个比特币，比特币最小单位为小数点后8位
static const int64 COIN = 100000000;
static const int64 CENT = 1000000;
static const int COINBASE_MATURITY = 100;// 币基成熟度
// 工作量证明的难度
static const CBigNum bnProofOfWorkLimit(~uint256(0) >> 32);






extern CCriticalSection cs_main;
extern map<uint256, CBlockIndex*> mapBlockIndex;
extern const uint256 hashGenesisBlock;
extern CBlockIndex* pindexGenesisBlock;
extern int nBestHeight;
extern uint256 hashBestChain;
extern CBlockIndex* pindexBest;
extern unsigned int nTransactionsUpdated;
extern string strSetDataDir;
extern int nDropMessagesTest;

// Settings
extern int fGenerateBitcoins;
extern int64 nTransactionFee;
extern CAddress addrIncoming;







string GetAppDir();
FILE* OpenBlockFile(unsigned int nFile, unsigned int nBlockPos, const char* pszMode="rb");
FILE* AppendBlockFile(unsigned int& nFileRet);
bool AddKey(const CKey& key);
vector<unsigned char> GenerateNewKey();
bool AddToWallet(const CWalletTx& wtxIn);
void ReacceptWalletTransactions();
void RelayWalletTransactions();
bool LoadBlockIndex(bool fAllowNew=true);
void PrintBlockTree();
bool BitcoinMiner();
bool ProcessMessages(CNode* pfrom);
bool ProcessMessage(CNode* pfrom, string strCommand, CDataStream& vRecv);
bool SendMessages(CNode* pto);
int64 GetBalance();
bool CreateTransaction(CScript scriptPubKey, int64 nValue, CWalletTx& txNew, int64& nFeeRequiredRet);
bool CommitTransactionSpent(const CWalletTx& wtxNew);
bool SendMoney(CScript scriptPubKey, int64 nValue, CWalletTx& wtxNew);











class CDiskTxPos
{
public:
    unsigned int nFile; // 块所在文件的信息，而且块文件的命名一般是blk${nFile}.dat
    unsigned int nBlockPos; // 当前块在对应块文件中的偏移
    unsigned int nTxPos; // 交易在对应块中的偏移

    CDiskTxPos()
    {
        SetNull();
    }

    CDiskTxPos(unsigned int nFileIn, unsigned int nBlockPosIn, unsigned int nTxPosIn)
    {
        nFile = nFileIn;
        nBlockPos = nBlockPosIn;
        nTxPos = nTxPosIn;
    }

    IMPLEMENT_SERIALIZE( READWRITE(FLATDATA(*this)); )
    void SetNull() { nFile = -1; nBlockPos = 0; nTxPos = 0; }
    bool IsNull() const { return (nFile == -1); }

    friend bool operator==(const CDiskTxPos& a, const CDiskTxPos& b)
    {
        return (a.nFile     == b.nFile &&
                a.nBlockPos == b.nBlockPos &&
                a.nTxPos    == b.nTxPos);
    }

    friend bool operator!=(const CDiskTxPos& a, const CDiskTxPos& b)
    {
        return !(a == b);
    }

    string ToString() const
    {
        if (IsNull())
            return strprintf("null");
        else
            return strprintf("(nFile=%d, nBlockPos=%d, nTxPos=%d)", nFile, nBlockPos, nTxPos);
    }

    void print() const
    {
        printf("%s", ToString().c_str());
    }
};




class CInPoint
{
public:
    CTransaction* ptx; // 交易指针
    unsigned int n; // 对应交易当前的第几个输入

    CInPoint() { SetNull(); }
    CInPoint(CTransaction* ptxIn, unsigned int nIn) { ptx = ptxIn; n = nIn; }
    void SetNull() { ptx = NULL; n = -1; }
    bool IsNull() const { return (ptx == NULL && n == -1); }
};




class COutPoint
{
public:
    uint256 hash; // 交易对应的hash
    unsigned int n; // 交易对应的第几个输出

    COutPoint() { SetNull(); }
    COutPoint(uint256 hashIn, unsigned int nIn) { hash = hashIn; n = nIn; }
    IMPLEMENT_SERIALIZE( READWRITE(FLATDATA(*this)); )
    void SetNull() { hash = 0; n = -1; }
    bool IsNull() const { return (hash == 0 && n == -1); }

    friend bool operator<(const COutPoint& a, const COutPoint& b)
    {
        return (a.hash < b.hash || (a.hash == b.hash && a.n < b.n));
    }

    friend bool operator==(const COutPoint& a, const COutPoint& b)
    {
        return (a.hash == b.hash && a.n == b.n);
    }

    friend bool operator!=(const COutPoint& a, const COutPoint& b)
    {
        return !(a == b);
    }

    string ToString() const
    {
        return strprintf("COutPoint(%s, %d)", hash.ToString().substr(0,6).c_str(), n);
    }

    void print() const
    {
        printf("%s\n", ToString().c_str());
    }
};




//
// An input of a transaction.  It contains the location of the previous
// transaction's output that it claims and a signature that matches the
// output's public key.
//
class CTxIn
{
public:
    COutPoint prevout; // 前一个交易对应的输出（叫一个交易对应的hash值和对应的第几个输出）
    CScript scriptSig; // 输入脚本对应的签名
    unsigned int nSequence;// 主要是用于判断相同输入的交易哪一个更新，值越大越新

    CTxIn()
    {
        nSequence = UINT_MAX;
    }

    explicit CTxIn(COutPoint prevoutIn, CScript scriptSigIn=CScript(), unsigned int nSequenceIn=UINT_MAX)
    {
        prevout = prevoutIn;
        scriptSig = scriptSigIn;
        nSequence = nSequenceIn;
    }

    CTxIn(uint256 hashPrevTx, unsigned int nOut, CScript scriptSigIn=CScript(), unsigned int nSequenceIn=UINT_MAX)
    {
        prevout = COutPoint(hashPrevTx, nOut);
        scriptSig = scriptSigIn;
        nSequence = nSequenceIn;
    }

    IMPLEMENT_SERIALIZE
    (
        READWRITE(prevout);
        READWRITE(scriptSig);
        READWRITE(nSequence);
    )
    // 交易对应nSequence是最大，已经是最新了，是最终的
    bool IsFinal() const
    {
        return (nSequence == UINT_MAX);
    }

    friend bool operator==(const CTxIn& a, const CTxIn& b)
    {
        return (a.prevout   == b.prevout &&
                a.scriptSig == b.scriptSig &&
                a.nSequence == b.nSequence);
    }

    friend bool operator!=(const CTxIn& a, const CTxIn& b)
    {
        return !(a == b);
    }

    string ToString() const
    {
        string str;
        str += strprintf("CTxIn(");
        str += prevout.ToString();
        if (prevout.IsNull())
            str += strprintf(", coinbase %s", HexStr(scriptSig.begin(), scriptSig.end(), false).c_str());
        else
            str += strprintf(", scriptSig=%s", scriptSig.ToString().substr(0,24).c_str());
        if (nSequence != UINT_MAX)
            str += strprintf(", nSequence=%u", nSequence);
        str += ")";
        return str;
    }

    void print() const
    {
        printf("%s\n", ToString().c_str());
    }

	// 判断当前输入的交易是否属于本节点，就是对应的脚本签名是否在本地能够找到
    bool IsMine() const;
	// 获得对应交易的借方金额，如果对应的输入是本节点的账号，则借方金额就是交易输入金额
    int64 GetDebit() const;
};




//
// An output of a transaction.  It contains the public key that the next input
// must be able to sign with to claim it.
//
class CTxOut
{
public:
    int64 nValue; // 交易输出对应的金额
    CScript scriptPubKey; // 交易对应的公钥

public:
    CTxOut()
    {
        SetNull();
    }

    CTxOut(int64 nValueIn, CScript scriptPubKeyIn)
    {
        nValue = nValueIn;
        scriptPubKey = scriptPubKeyIn;
    }

    IMPLEMENT_SERIALIZE
    (
        READWRITE(nValue);
        READWRITE(scriptPubKey);
    )

    void SetNull()
    {
        nValue = -1;
        scriptPubKey.clear();
    }

    bool IsNull()
    {
        return (nValue == -1);
    }

    uint256 GetHash() const
    {
        return SerializeHash(*this);
    }

	// 判断交易的输出是否是节点自己本身对应的交易，也是在当前中根据公钥能够找到对应的私钥
    bool IsMine() const
    {
        return ::IsMine(scriptPubKey);
    }

	// 获取当前交易数据贷方金额，如果是节点本身的交易则返回对应输出的金额，否则对节点来说其对应的贷方金额为0
    int64 GetCredit() const
    {
        if (IsMine())
            return nValue;
        return 0;
    }

    friend bool operator==(const CTxOut& a, const CTxOut& b)
    {
        return (a.nValue       == b.nValue &&
                a.scriptPubKey == b.scriptPubKey);
    }

    friend bool operator!=(const CTxOut& a, const CTxOut& b)
    {
        return !(a == b);
    }

    string ToString() const
    {
        if (scriptPubKey.size() < 6)
            return "CTxOut(error)";
        return strprintf("CTxOut(nValue=%I64d.%08I64d, scriptPubKey=%s)", nValue / COIN, nValue % COIN, scriptPubKey.ToString().substr(0,24).c_str());
    }

    void print() const
    {
        printf("%s\n", ToString().c_str());
    }
};




//
// The basic transaction that is broadcasted on the network and contained in
// blocks.  A transaction can contain multiple inputs and outputs.
//
class CTransaction
{
public:
    int nVersion; // 交易的版本号，用于升级
    vector<CTxIn> vin; // 交易对应的输入
    vector<CTxOut> vout; // 交易对应的输出
    int nLockTime; // 交易对应的锁定时间


    CTransaction()
    {
        SetNull();
    }

    IMPLEMENT_SERIALIZE
    (
        READWRITE(this->nVersion);
        nVersion = this->nVersion;
        READWRITE(vin);
        READWRITE(vout);
        READWRITE(nLockTime);
    )

    void SetNull()
    {
        nVersion = 1;
        vin.clear();
        vout.clear();
        nLockTime = 0;
    }

    bool IsNull() const
    {
        return (vin.empty() && vout.empty());
    }

    uint256 GetHash() const
    {
        return SerializeHash(*this);
    }

    // 判断是否是最终的交易
    bool IsFinal() const
    {
        // 如果锁定时间等于0或者锁定时间小于主链的长度，则说明是最终的交易
        if (nLockTime == 0 || nLockTime < nBestHeight)
            return true;
        foreach(const CTxIn& txin, vin)
            if (!txin.IsFinal())
                return false;
        return true;
    }
	// 对比相同的交易哪一个更新点：对于相同输入的交易判断哪一个更新
    bool IsNewerThan(const CTransaction& old) const
    {
        if (vin.size() != old.vin.size())
            return false;
        for (int i = 0; i < vin.size(); i++)
            if (vin[i].prevout != old.vin[i].prevout)
                return false;

        bool fNewer = false;
        unsigned int nLowest = UINT_MAX;
        for (int i = 0; i < vin.size(); i++)
        {
            if (vin[i].nSequence != old.vin[i].nSequence)
            {
                if (vin[i].nSequence <= nLowest)
                {
                    fNewer = false;
                    nLowest = vin[i].nSequence;
                }
                if (old.vin[i].nSequence < nLowest)
                {
                    fNewer = true;
                    nLowest = old.vin[i].nSequence;
                }
            }
        }
        return fNewer;
    }

	// 判断当前交易是否是币基交易：币基交易的特点是交易输入大小为1，但是对应的输入的输出为空
    bool IsCoinBase() const
    {
        return (vin.size() == 1 && vin[0].prevout.IsNull());
    }
	/* 对这边交易进行检查：
	(1)交易对应的输入或者输出列表都不能为空
	(2)交易对应的输出金额不能小于0
	(3)如果是币基交易，则对应的输入只能为1，且对应的输入签名大小不能大于100
	(4)如果是非币基交易，则对应的交易输入的输出不能为空
	*/
    bool CheckTransaction() const
    {
        // Basic checks that don't depend on any context
        if (vin.empty() || vout.empty())
            return error("CTransaction::CheckTransaction() : vin or vout empty");

        // Check for negative values
        foreach(const CTxOut& txout, vout)
            if (txout.nValue < 0)
                return error("CTransaction::CheckTransaction() : txout.nValue negative");

        if (IsCoinBase())
        {
            if (vin[0].scriptSig.size() < 2 || vin[0].scriptSig.size() > 100)
                return error("CTransaction::CheckTransaction() : coinbase script size");
        }
        else
        {
            foreach(const CTxIn& txin, vin)
                if (txin.prevout.IsNull())
                    return error("CTransaction::CheckTransaction() : prevout is null");
        }

        return true;
    }

	// 判断当前的交易是否包含节点本身的交易（在输出列表中）
    bool IsMine() const
    {
        foreach(const CTxOut& txout, vout)
            if (txout.IsMine())
                return true;
        return false;
    }

	// 获得当前交易总的输入：借方
    int64 GetDebit() const
    {
        int64 nDebit = 0;
        foreach(const CTxIn& txin, vin)
            nDebit += txin.GetDebit();
        return nDebit;
    }

	// 获得当前交易总的贷方金额：属于节点自身的
    int64 GetCredit() const
    {
        int64 nCredit = 0;
        foreach(const CTxOut& txout, vout)
            nCredit += txout.GetCredit();
        return nCredit;
    }
	// 获取交易对应所有输出金额之和
    int64 GetValueOut() const
    {
        int64 nValueOut = 0;
        foreach(const CTxOut& txout, vout)
        {
            if (txout.nValue < 0)
                throw runtime_error("CTransaction::GetValueOut() : negative value");
            nValueOut += txout.nValue;
        }
        return nValueOut;
    }
	// 获取交易对应的最小交易费：大小小于10000字节则对应的最小交易费为0，否则为按照大小进行计算交易费
	// Transaction fee requirements, mainly only needed for flood control
	// Under 10K (about 80 inputs) is free for first 100 transactions
	// Base rate is 0.01 per KB
    int64 GetMinFee(bool fDiscount=false) const
    {
        unsigned int nBytes = ::GetSerializeSize(*this, SER_NETWORK);
        if (fDiscount && nBytes < 10000)
            return 0;
        return (1 + (int64)nBytes / 1000) * CENT;
    }

	// 从硬盘中进行读取
    bool ReadFromDisk(CDiskTxPos pos, FILE** pfileRet=NULL)
    {
        CAutoFile filein = OpenBlockFile(pos.nFile, 0, pfileRet ? "rb+" : "rb");
        if (!filein)
            return error("CTransaction::ReadFromDisk() : OpenBlockFile failed");

        // Read transaction
        if (fseek(filein, pos.nTxPos, SEEK_SET) != 0)
            return error("CTransaction::ReadFromDisk() : fseek failed");
        filein >> *this;

        // Return file pointer
        if (pfileRet)
        {
            if (fseek(filein, pos.nTxPos, SEEK_SET) != 0)
                return error("CTransaction::ReadFromDisk() : second fseek failed");
            *pfileRet = filein.release();
        }
        return true;
    }


    friend bool operator==(const CTransaction& a, const CTransaction& b)
    {
        return (a.nVersion  == b.nVersion &&
                a.vin       == b.vin &&
                a.vout      == b.vout &&
                a.nLockTime == b.nLockTime);
    }

    friend bool operator!=(const CTransaction& a, const CTransaction& b)
    {
        return !(a == b);
    }


    string ToString() const
    {
        string str;
        str += strprintf("CTransaction(hash=%s, ver=%d, vin.size=%d, vout.size=%d, nLockTime=%d)\n",
            GetHash().ToString().substr(0,6).c_str(),
            nVersion,
            vin.size(),
            vout.size(),
            nLockTime);
        for (int i = 0; i < vin.size(); i++)
            str += "    " + vin[i].ToString() + "\n";
        for (int i = 0; i < vout.size(); i++)
            str += "    " + vout[i].ToString() + "\n";
        return str;
    }

    void print() const
    {
        printf("%s", ToString().c_str());
    }


	// 断开连接：释放交易对应输入的占用和将交易从对应的交易索引表中释放掉
    bool DisconnectInputs(CTxDB& txdb);
	// 交易输入链接，将对应的交易输入占用对应的交易输入的花费标记
    bool ConnectInputs(CTxDB& txdb, map<uint256, CTxIndex>& mapTestPool, CDiskTxPos posThisTx, int nHeight, int64& nFees, bool fBlock, bool fMiner, int64 nMinFee=0);
	// 客户端连接输入，对交易本身进行验证
	bool ClientConnectInputs();
	// 判断这笔交易是否应该被接受
    bool AcceptTransaction(CTxDB& txdb, bool fCheckInputs=true, bool* pfMissingInputs=NULL);

    bool AcceptTransaction(bool fCheckInputs=true, bool* pfMissingInputs=NULL)
    {
        CTxDB txdb("r");
        return AcceptTransaction(txdb, fCheckInputs, pfMissingInputs);
    }

protected:
	// 将当前交易增加到内存池mapTransactions,mapNextTx中，并且更新交易更新的次数
    bool AddToMemoryPool();
public:
	// 将当前交易从内存对象mapTransactions，mapNextTx中移除，并且增加交易对应的更新次数
    bool RemoveFromMemoryPool();
};





//
// A transaction with a merkle branch linking it to the block chain
//
class CMerkleTx : public CTransaction
{
public:
    uint256 hashBlock;// 交易所在block对应的hash值，因为block中有对应整个交易的默克尔树，这样才能根据分支来校验当前交易是否在block中
    vector<uint256> vMerkleBranch; // 当前交易对应的默克尔分支
    int nIndex;// 当前交易在对应的block对应的输入vtx列表中的索引，CMerkleTx就是根据索引来计算这个交易对应的默克尔树分支的

    // memory only
    mutable bool fMerkleVerified;// 标记默克尔交易是否已经校验，如果没有校验则进行校验，校验之后将这个值设为true


    CMerkleTx()
    {
        Init();
    }

    CMerkleTx(const CTransaction& txIn) : CTransaction(txIn)
    {
        Init();
    }

    void Init()
    {
        hashBlock = 0;
        nIndex = -1;
        fMerkleVerified = false;
    }

	// 获取默克尔树对应的贷方金额的时候，对于币基交易，一定要等对应的block足够成熟了才能使用
    int64 GetCredit() const
    {
        // Must wait until coinbase is safely deep enough in the chain before valuing it
        if (IsCoinBase() && GetBlocksToMaturity() > 0)
            return 0;
        return CTransaction::GetCredit();
    }

    IMPLEMENT_SERIALIZE
    (
        nSerSize += SerReadWrite(s, *(CTransaction*)this, nType, nVersion, ser_action);
        nVersion = this->nVersion;
        READWRITE(hashBlock);
        READWRITE(vMerkleBranch);
        READWRITE(nIndex);
    )

    // 如果交易在对应的区块中，则设置交易对应的默克尔树分支
    int SetMerkleBranch(const CBlock* pblock=NULL);
	//获取默克尔交易在主链中的深度--当前块距离最长链末尾中间隔了多少个block
    int GetDepthInMainChain() const;
	// 判断当前交易是否在主链上
    bool IsInMainChain() const { return GetDepthInMainChain() > 0; }
	// 判断对应的块是否成熟，即是被其他矿工所接受认可，如果是非币基交易对应的为块成熟度为0，否则要进行计算
    // 成熟度越小越好，说明当前交易被认可的度越高
    int GetBlocksToMaturity() const;
	// 判断这边交易能不能被接受，如果能接受将对应的交易放入全局变量中mapTransactions，mapNextTx中
    bool AcceptTransaction(CTxDB& txdb, bool fCheckInputs=true);
    bool AcceptTransaction() { CTxDB txdb("r"); return AcceptTransaction(txdb); }
};




//
// A transaction with a bunch of additional info that only the owner cares
// about.  It includes any unrecorded transactions needed to link it back
// to the block chain.
//
class CWalletTx : public CMerkleTx
{
public:
    vector<CMerkleTx> vtxPrev; // 当前交易A对应的输入对应的交易B，如果B所在block到最长链末尾的长度小于3，则将次交易放入
    /*
	主要用于存放一下自定义的值
	wtx.mapValue["to"] = strAddress;
	wtx.mapValue["from"] = m_textCtrlFrom->GetValue();
	wtx.mapValue["message"] = m_textCtrlMessage->GetValue();
	*/
	map<string, string> mapValue;
	// 表单控件信息
    vector<pair<string, string> > vOrderForm;
    unsigned int fTimeReceivedIsTxTime;// 接收时间是否是交易时间标记
    unsigned int nTimeReceived;  // time received by this node 交易被这个节点接收的时间
    char fFromMe;
    char fSpent; // 是否花费交易标记
    //// probably need to sign the order info so know it came from payer

    // memory only
    mutable unsigned int nTimeDisplayed;


    CWalletTx()
    {
        Init();
    }

    CWalletTx(const CMerkleTx& txIn) : CMerkleTx(txIn)
    {
        Init();
    }

    CWalletTx(const CTransaction& txIn) : CMerkleTx(txIn)
    {
        Init();
    }

    void Init()
    {
        fTimeReceivedIsTxTime = false;
        nTimeReceived = 0;
        fFromMe = false;
        fSpent = false;
        nTimeDisplayed = 0;
    }

    IMPLEMENT_SERIALIZE
    (
        nSerSize += SerReadWrite(s, *(CMerkleTx*)this, nType, nVersion, ser_action);
        nVersion = this->nVersion;
        READWRITE(vtxPrev);
        READWRITE(mapValue);
        READWRITE(vOrderForm);
        READWRITE(fTimeReceivedIsTxTime);
        READWRITE(nTimeReceived);
        READWRITE(fFromMe);
        READWRITE(fSpent);
    )

    bool WriteToDisk()
    {
        return CWalletDB().WriteTx(GetHash(), *this);
    }

	// 获取交易时间
    int64 GetTxTime() const;
	// 增加支持的交易
    void AddSupportingTransactions(CTxDB& txdb);
	// 判断当前交易能够被接收
    bool AcceptWalletTransaction(CTxDB& txdb, bool fCheckInputs=true);
    bool AcceptWalletTransaction() { CTxDB txdb("r"); return AcceptWalletTransaction(txdb); }
	// 转播钱包交易
    void RelayWalletTransaction(CTxDB& txdb);
    void RelayWalletTransaction() { CTxDB txdb("r"); RelayWalletTransaction(txdb); }
};




//
// A txdb record that contains the disk location of a transaction and the
// locations of transactions that spend its outputs.  vSpent is really only
// used as a flag, but having the location is very helpful for debugging.
//
// 交易索引---每一个交易对应一个索引
class CTxIndex
{
public:
    CDiskTxPos pos; // 交易对应的在硬盘中文件的位置
    vector<CDiskTxPos> vSpent; // 标记交易的输出是否已经被消费了，根据下标来标记对应交易指定位置的输出是否已经被消费了

    CTxIndex()
    {
        SetNull();
    }

    CTxIndex(const CDiskTxPos& posIn, unsigned int nOutputs)
    {
        pos = posIn;
        vSpent.resize(nOutputs);
    }

    IMPLEMENT_SERIALIZE
    (
        if (!(nType & SER_GETHASH))
            READWRITE(nVersion);
        READWRITE(pos);
        READWRITE(vSpent);
    )

    void SetNull()
    {
        pos.SetNull();
        vSpent.clear();
    }

    bool IsNull()
    {
        return pos.IsNull();
    }

    friend bool operator==(const CTxIndex& a, const CTxIndex& b)
    {
        if (a.pos != b.pos || a.vSpent.size() != b.vSpent.size())
            return false;
        for (int i = 0; i < a.vSpent.size(); i++)
            if (a.vSpent[i] != b.vSpent[i])
                return false;
        return true;
    }

    friend bool operator!=(const CTxIndex& a, const CTxIndex& b)
    {
        return !(a == b);
    }
};





//
// Nodes collect new transactions into a block, hash them into a hash tree,
// and scan through nonce values to make the block's hash satisfy proof-of-work
// requirements.  When they solve the proof-of-work, they broadcast the block
// to everyone and the block is added to the block chain.  The first transaction
// in the block is a special one that creates a new coin owned by the creator
// of the block.
//
// Blocks are appended to blk0001.dat files on disk.  Their location on disk
// is indexed by CBlockIndex objects in memory.
//
// 块定义
class CBlock
{
public:
    // header
    int nVersion; // 块的版本，主要为了后续的升级使用
    uint256 hashPrevBlock; // 前一个块对应的hash
    uint256 hashMerkleRoot; // 默克尔对应的根
	// 取前11个区块对应的创建时间平均值
    unsigned int nTime; // 单位为秒，取区块链中对应的前多少个区块对应时间的中位数，如果不存在前一个则去当前时间
    unsigned int nBits; // 记录本区块难度
    unsigned int nNonce; // 工作量证明获得随机数，这个随机数正好满足当前挖矿对应的难度

    // network and disk
    vector<CTransaction> vtx; // 块中交易列表

    // memory only
    mutable vector<uint256> vMerkleTree; // 整个交易对应的默克尔树列表


    CBlock()
    {
        SetNull();
    }

    IMPLEMENT_SERIALIZE
    (
        READWRITE(this->nVersion);
        nVersion = this->nVersion;
        READWRITE(hashPrevBlock);
        READWRITE(hashMerkleRoot);
        READWRITE(nTime);
        READWRITE(nBits);
        READWRITE(nNonce);

        // ConnectBlock depends on vtx being last so it can calculate offset
        if (!(nType & (SER_GETHASH|SER_BLOCKHEADERONLY)))
            READWRITE(vtx);
        else if (fRead)
            const_cast<CBlock*>(this)->vtx.clear();
    )

    void SetNull()
    {
        nVersion = 1;
        hashPrevBlock = 0;
        hashMerkleRoot = 0;
        nTime = 0;
        nBits = 0;
        nNonce = 0;
        vtx.clear();
        vMerkleTree.clear();
    }

    bool IsNull() const
    {
        return (nBits == 0);
    }

	// 块hash值仅仅包含从nVersion 到 nNonce 的值
    uint256 GetHash() const
    {
        return Hash(BEGIN(nVersion), END(nNonce));
    }

	// 根据交易构建对应的默克尔树
    uint256 BuildMerkleTree() const
    {
        vMerkleTree.clear();
        foreach(const CTransaction& tx, vtx)
            vMerkleTree.push_back(tx.GetHash());
        int j = 0;
        for (int nSize = vtx.size(); nSize > 1; nSize = (nSize + 1) / 2)
        {
            for (int i = 0; i < nSize; i += 2)
            {
                int i2 = min(i+1, nSize-1);
                vMerkleTree.push_back(Hash(BEGIN(vMerkleTree[j+i]),  END(vMerkleTree[j+i]),
                                           BEGIN(vMerkleTree[j+i2]), END(vMerkleTree[j+i2])));
            }
            j += nSize;
        }
        return (vMerkleTree.empty() ? 0 : vMerkleTree.back());
    }
	// 根据交易对应的索引获得交易对应的默克尔分支
    vector<uint256> GetMerkleBranch(int nIndex) const
    {
        if (vMerkleTree.empty())
            BuildMerkleTree();
        vector<uint256> vMerkleBranch;
        int j = 0;
        for (int nSize = vtx.size(); nSize > 1; nSize = (nSize + 1) / 2)
        {
            int i = min(nIndex^1, nSize-1);
            vMerkleBranch.push_back(vMerkleTree[j+i]);
            nIndex >>= 1;
            j += nSize;
        }
        return vMerkleBranch;
    }
	// 判断当前对应的交易hash和默克尔分支来验证对应的交易是否在对应的blcok中
    static uint256 CheckMerkleBranch(uint256 hash, const vector<uint256>& vMerkleBranch, int nIndex)
    {
        if (nIndex == -1)
            return 0;
        foreach(const uint256& otherside, vMerkleBranch)
        {
            if (nIndex & 1)
                hash = Hash(BEGIN(otherside), END(otherside), BEGIN(hash), END(hash));
            else
                hash = Hash(BEGIN(hash), END(hash), BEGIN(otherside), END(otherside));
            nIndex >>= 1;
        }
        return hash;
    }

	// 将block写入到文件中
    bool WriteToDisk(bool fWriteTransactions, unsigned int& nFileRet, unsigned int& nBlockPosRet)
    {
        // Open history file to append
        CAutoFile fileout = AppendBlockFile(nFileRet);
        if (!fileout)
            return error("CBlock::WriteToDisk() : AppendBlockFile failed");
        if (!fWriteTransactions)
            fileout.nType |= SER_BLOCKHEADERONLY;

        // Write index header
        unsigned int nSize = fileout.GetSerializeSize(*this);
		// 放入消息头和对应块的大小值
        fileout << FLATDATA(pchMessageStart) << nSize;

        // Write block
        nBlockPosRet = ftell(fileout);
        if (nBlockPosRet == -1)
            return error("CBlock::WriteToDisk() : ftell failed");
		// 将block的内容写入到文件中
        fileout << *this;

        return true;
    }

	// 从文件中读取块信息
    bool ReadFromDisk(unsigned int nFile, unsigned int nBlockPos, bool fReadTransactions)
    {
        SetNull();

        // Open history file to read
        CAutoFile filein = OpenBlockFile(nFile, nBlockPos, "rb");
        if (!filein)
            return error("CBlock::ReadFromDisk() : OpenBlockFile failed");
        if (!fReadTransactions)
            filein.nType |= SER_BLOCKHEADERONLY;

        // Read block 将文件中的内容读取到块中
        filein >> *this;

        // Check the header 1. 工作量证明难度比较 2. 计算的hash值要小于对应的工作量难度
        if (CBigNum().SetCompact(nBits) > bnProofOfWorkLimit)
            return error("CBlock::ReadFromDisk() : nBits errors in block header");
        if (GetHash() > CBigNum().SetCompact(nBits).getuint256())
            return error("CBlock::ReadFromDisk() : GetHash() errors in block header");

        return true;
    }



    void print() const
    {
        printf("CBlock(hash=%s, ver=%d, hashPrevBlock=%s, hashMerkleRoot=%s, nTime=%u, nBits=%08x, nNonce=%u, vtx=%d)\n",
            GetHash().ToString().substr(0,14).c_str(),
            nVersion,
            hashPrevBlock.ToString().substr(0,14).c_str(),
            hashMerkleRoot.ToString().substr(0,6).c_str(),
            nTime, nBits, nNonce,
            vtx.size());
        for (int i = 0; i < vtx.size(); i++)
        {
            printf("  ");
            vtx[i].print();
        }
        printf("  vMerkleTree: ");
        for (int i = 0; i < vMerkleTree.size(); i++)
            printf("%s ", vMerkleTree[i].ToString().substr(0,6).c_str());
        printf("\n");
    }

	// 获取这个区块对应的价值（奖励+交易手续费）
    int64 GetBlockValue(int64 nFees) const;
	// 将一个区块block断开连接（就是释放区块对应的信息，同时释放区块对应的区块索引）
    bool DisconnectBlock(CTxDB& txdb, CBlockIndex* pindex);
	// 区块链接：每一个交易链接，增加到区块索引链中
    bool ConnectBlock(CTxDB& txdb, CBlockIndex* pindex);
	// 根据区块索引从数据库文件中读取对应的区块信息
    bool ReadFromDisk(const CBlockIndex* blockindex, bool fReadTransactions);
	// 将当前区块增加到对应的区块索引中
    bool AddToBlockIndex(unsigned int nFile, unsigned int nBlockPos);
	// 区块校验
    bool CheckBlock() const;
	// 判断当前区块能够被接收
    bool AcceptBlock();
};






//
// The block chain is a tree shaped structure starting with the
// genesis block at the root, with each block potentially having multiple
// candidates to be the next block.  pprev and pnext link a path through the
// main/longest chain.  A blockindex may have multiple pprev pointing back
// to it, but pnext will only point forward to the longest branch, or will
// be null if the block is not part of the longest chain.
//
// 如果块索引对应的pNext不为空，则这个块索引一定对应的是主链
// 块索引
class CBlockIndex
{
public:
    const uint256* phashBlock; // 对应块hash值指针
    CBlockIndex* pprev; // 指向前一个blockIndex
    CBlockIndex* pnext; // 指向当前区块索引的下一个，只有当前区块索引在主链上的时候，这个值才是非空
	// 块所在文件中的信息
    unsigned int nFile; 
    unsigned int nBlockPos;
    int nHeight; // 块索引在最长链的深度，即是中间隔了多少个block，即是从创世区块到当前区块中间隔了多少个区块

    // block header 块的头部信息
    int nVersion;
    uint256 hashMerkleRoot;
	// 取前11个区块对应的创建时间平均值
    unsigned int nTime;// 块创建时间，取块链上时间中位数
    unsigned int nBits;
    unsigned int nNonce;


    CBlockIndex()
    {
        phashBlock = NULL;
        pprev = NULL;
        pnext = NULL;
        nFile = 0;
        nBlockPos = 0;
        nHeight = 0;

        nVersion       = 0;
        hashMerkleRoot = 0;
        nTime          = 0;
        nBits          = 0;
        nNonce         = 0;
    }

    CBlockIndex(unsigned int nFileIn, unsigned int nBlockPosIn, CBlock& block)
    {
        phashBlock = NULL;
        pprev = NULL;
        pnext = NULL;
        nFile = nFileIn;
        nBlockPos = nBlockPosIn;
        nHeight = 0;

        nVersion       = block.nVersion;
        hashMerkleRoot = block.hashMerkleRoot;
        nTime          = block.nTime;
        nBits          = block.nBits;
        nNonce         = block.nNonce;
    }

    uint256 GetBlockHash() const
    {
        return *phashBlock;
    }

	// 判断是否在主链，通过pnext是否为空和当前块索引指针是否就是最长链指针
    bool IsInMainChain() const
    {
        return (pnext || this == pindexBest);
    }

	// 从文件中移除对应的块
    bool EraseBlockFromDisk()
    {
        // Open history file
        CAutoFile fileout = OpenBlockFile(nFile, nBlockPos, "rb+");
        if (!fileout)
            return false;

		// 在文件对应的位置重新写一个空块，这样就相当于从文件中删除对应的当期块
        // Overwrite with empty null block
        CBlock block;
        block.SetNull();
        fileout << block;

        return true;
    }

	// 取前11个区块对应的创建时间平均值
    enum { nMedianTimeSpan=11 };

	// 从当前块往前推，获取过去对应的中位数时间，在对应的区块链中获取每一个区块对应的时间，然后取中位数
    int64 GetMedianTimePast() const
    {
        unsigned int pmedian[nMedianTimeSpan];
        unsigned int* pbegin = &pmedian[nMedianTimeSpan];
        unsigned int* pend = &pmedian[nMedianTimeSpan];

        const CBlockIndex* pindex = this;
        for (int i = 0; i < nMedianTimeSpan && pindex; i++, pindex = pindex->pprev)
            *(--pbegin) = pindex->nTime;

        sort(pbegin, pend);
        return pbegin[(pend - pbegin)/2];
    }
	// 从当前块往后推，取中位数时间
    int64 GetMedianTime() const
    {
        const CBlockIndex* pindex = this;
        for (int i = 0; i < nMedianTimeSpan/2; i++)
        {
            if (!pindex->pnext)
                return nTime;
            pindex = pindex->pnext;
        }
        return pindex->GetMedianTimePast();
    }



    string ToString() const
    {
        return strprintf("CBlockIndex(nprev=%08x, pnext=%08x, nFile=%d, nBlockPos=%-6d nHeight=%d, merkle=%s, hashBlock=%s)",
            pprev, pnext, nFile, nBlockPos, nHeight,
            hashMerkleRoot.ToString().substr(0,6).c_str(),
            GetBlockHash().ToString().substr(0,14).c_str());
    }

    void print() const
    {
        printf("%s\n", ToString().c_str());
    }
};



//
// Used to marshal pointers into hashes for db storage.
// 用于将指针替换成hash值用于数据库存储
//
class CDiskBlockIndex : public CBlockIndex
{
public:
    uint256 hashPrev; // block对应的hash值，将指针变成对应的hash
    uint256 hashNext;

    CDiskBlockIndex()
    {
        hashPrev = 0;
        hashNext = 0;
    }

    explicit CDiskBlockIndex(CBlockIndex* pindex) : CBlockIndex(*pindex)
    {
        hashPrev = (pprev ? pprev->GetBlockHash() : 0);
        hashNext = (pnext ? pnext->GetBlockHash() : 0);
    }

    IMPLEMENT_SERIALIZE
    (
        if (!(nType & SER_GETHASH))
            READWRITE(nVersion);

        READWRITE(hashNext);
        READWRITE(nFile);
        READWRITE(nBlockPos);
        READWRITE(nHeight);

        // block header
        READWRITE(this->nVersion);
        READWRITE(hashPrev);
        READWRITE(hashMerkleRoot);
        READWRITE(nTime);
        READWRITE(nBits);
        READWRITE(nNonce);
    )

    uint256 GetBlockHash() const
    {
        CBlock block;
        block.nVersion        = nVersion;
        block.hashPrevBlock   = hashPrev;
        block.hashMerkleRoot  = hashMerkleRoot;
        block.nTime           = nTime;
        block.nBits           = nBits;
        block.nNonce          = nNonce;
        return block.GetHash(); // 块的hash仅仅包含上面这些内容
    }


    string ToString() const
    {
        string str = "CDiskBlockIndex(";
        str += CBlockIndex::ToString();
        str += strprintf("\n                hashBlock=%s, hashPrev=%s, hashNext=%s)",
            GetBlockHash().ToString().c_str(),
            hashPrev.ToString().substr(0,14).c_str(),
            hashNext.ToString().substr(0,14).c_str());
        return str;
    }

    void print() const
    {
        printf("%s\n", ToString().c_str());
    }
};








//
// Describes a place in the block chain to another node such that if the
// other node doesn't have the same branch, it can find a recent common trunk.
// The further back it is, the further before the fork it may be.
//
class CBlockLocator
{
protected:
    vector<uint256> vHave; // 区块链对应的block索引
public:

    CBlockLocator()
    {
    }

    explicit CBlockLocator(const CBlockIndex* pindex)
    {
        Set(pindex);
    }

    explicit CBlockLocator(uint256 hashBlock)
    {
        map<uint256, CBlockIndex*>::iterator mi = mapBlockIndex.find(hashBlock);
        if (mi != mapBlockIndex.end())
            Set((*mi).second);
    }

    IMPLEMENT_SERIALIZE
    (
        if (!(nType & SER_GETHASH))
            READWRITE(nVersion);
        READWRITE(vHave);
    )

    void Set(const CBlockIndex* pindex)
    {
        vHave.clear();
        int nStep = 1;
        while (pindex)
        {
            vHave.push_back(pindex->GetBlockHash());

			// 指数快速回退算法：前10个保存，后面是指数回退一直到区块链头部为止
            // Exponentially larger steps back
            for (int i = 0; pindex && i < nStep; i++)
                pindex = pindex->pprev;
            if (vHave.size() > 10)
                nStep *= 2;
        }
        vHave.push_back(hashGenesisBlock); // 默认放置一个创世区块
    }
	// 找到本地有的且在主链上的块的索引
    CBlockIndex* GetBlockIndex()
    {
        // Find the first block the caller has in the main chain
        foreach(const uint256& hash, vHave)
        {
			// 找到本地有的且在主链上的
            map<uint256, CBlockIndex*>::iterator mi = mapBlockIndex.find(hash);
            if (mi != mapBlockIndex.end())
            {
                CBlockIndex* pindex = (*mi).second;
                if (pindex->IsInMainChain())
                    return pindex;
            }
        }
        return pindexGenesisBlock;
    }

    uint256 GetBlockHash()
    {
        // Find the first block the caller has in the main chain
        foreach(const uint256& hash, vHave)
        {
            map<uint256, CBlockIndex*>::iterator mi = mapBlockIndex.find(hash);
            if (mi != mapBlockIndex.end())
            {
                CBlockIndex* pindex = (*mi).second;
                if (pindex->IsInMainChain())
                    return hash;
            }
        }
        return hashGenesisBlock;
    }

    int GetHeight()
    {
        CBlockIndex* pindex = GetBlockIndex();
        if (!pindex)
            return 0;
        return pindex->nHeight;
    }
};












extern map<uint256, CTransaction> mapTransactions;
extern map<uint256, CWalletTx> mapWallet;
extern vector<pair<uint256, bool> > vWalletUpdated;
extern CCriticalSection cs_mapWallet;
extern map<vector<unsigned char>, CPrivKey> mapKeys;
extern map<uint160, vector<unsigned char> > mapPubKeys;
extern CCriticalSection cs_mapKeys;
extern CKey keyUser;
