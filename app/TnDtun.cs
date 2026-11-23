using System;using System.IO;using System.Text;using System.Linq;using System.Collections.Generic;using System.Collections.Concurrent;using System.Diagnostics;using System.Drawing;using System.Threading;using System.Threading.Tasks;using System.Windows.Forms;using System.Web.Script.Serialization;using System.Web;using System.IO.Pipes;using System.Security.Principal;
namespace TnDtun {
static class J {public static JavaScriptSerializer New(){return new JavaScriptSerializer{MaxJsonLength=32*1024*1024,RecursionLimit=80};}public static string Encode(object o){return New().Serialize(o);}public static Dictionary<string,object> Obj(object o){return o as Dictionary<string,object>??new Dictionary<string,object>();}public static object Get(object o,string k){object v;return Obj(o).TryGetValue(k,out v)?v:null;}public static string Text(object o,string k){return Convert.ToString(Get(o,k))??"";}public static bool Bool(object o,string k){return Get(o,k) is bool&&(bool)Get(o,k);}public static object[] Rows(object o){return o as object[]??new object[0];}public static long Num(object o,string k){long n;return long.TryParse(Text(o,k),out n)?n:0;}public static Dictionary<string,object> D(params object[] v){var d=new Dictionary<string,object>();for(int i=0;i<v.Length;i+=2)d[(string)v[i]]=v[i+1];return d;}}
class Rpc:IDisposable {Process process;readonly object gate=new object();ConcurrentDictionary<string,TaskCompletionSource<object>> pending=new ConcurrentDictionary<string,TaskCompletionSource<object>>();public event Action<Dictionary<string,object>> State;public event Action<string> Fatal;public Dictionary<string,object> Last=new Dictionary<string,object>();public string TestHome;
 public void Start(){lock(gate){if(process!=null&&!process.HasExited)return;var p=new Process();p.StartInfo=new ProcessStartInfo(Path.Combine(AppDomain.CurrentDomain.BaseDirectory,"TnDtun.Engine.exe")){UseShellExecute=false,CreateNoWindow=true,RedirectStandardInput=true,RedirectStandardOutput=true,RedirectStandardError=true,StandardOutputEncoding=Encoding.UTF8,StandardErrorEncoding=Encoding.UTF8,WorkingDirectory=AppDomain.CurrentDomain.BaseDirectory};if(TestHome!=null)p.StartInfo.EnvironmentVariables["TNDTUN_TEST_DATA"]=TestHome;p.OutputDataReceived+=(s,e)=>{if(e.Data==null)return;try{var m=J.New().DeserializeObject(e.Data) as Dictionary<string,object>;if(m==null)return;string id=J.Text(m,"id");TaskCompletionSource<object> t;if(id!=""&&pending.TryRemove(id,out t)){if(J.Bool(m,"ok"))t.TrySetResult(J.Get(m,"data"));else t.TrySetException(new Exception(J.Text(m,"error")));}else if(J.Text(m,"event")=="state"){Last=J.Obj(J.Get(m,"data"));var h=State;if(h!=null)h(Last);}else if(J.Text(m,"event")=="fatal"){var h=Fatal;if(h!=null)h(J.Text(m,"error"));}}catch{}};p.ErrorDataReceived+=(s,e)=>{};p.EnableRaisingEvents=true;p.Exited+=(s,e)=>{if(process!=p)return;foreach(var kv in pending){TaskCompletionSource<object> t;if(pending.TryRemove(kv.Key,out t))t.TrySetException(new Exception("Сетевой процесс завершился"));}var h=Fatal;if(h!=null)h("Сетевой процесс завершился. Подключение остановлено.");};process=p;if(!p.Start())throw new Exception("Не удалось запустить сетевой процесс");p.StandardInput.AutoFlush=true;p.BeginOutputReadLine();p.BeginErrorReadLine();}}
 public async Task<object> Call(string op,object data=null){Start();string id=Guid.NewGuid().ToString("N");var t=new TaskCompletionSource<object>();pending[id]=t;lock(gate){process.StandardInput.WriteLine(J.Encode(J.D("id",id,"op",op,"data",data??J.D())));}var completed=await Task.WhenAny(t.Task,Task.Delay(op=="activate"||op=="sync"?220000:35000));if(completed!=t.Task){TaskCompletionSource<object> ignored;pending.TryRemove(id,out ignored);throw new Exception("Операция заняла слишком много времени. Можно отменить её и повторить.");}return await t.Task;}
 public void Dispose(){lock(gate){if(process==null)return;try{if(!process.HasExited){process.StandardInput.WriteLine(J.Encode(J.D("id","quit","op","quit")));process.StandardInput.Close();if(!process.WaitForExit(12000))process.Kill();}}catch{}process.Dispose();process=null;}}
}
static class Style {public static Color Navy=Color.FromArgb(22,36,57),Blue=Color.FromArgb(33,104,210),Ink=Color.FromArgb(32,45,61);public static void Form(Form f){f.Font=new Font("Segoe UI",10);f.BackColor=Color.FromArgb(246,248,251);f.ForeColor=Ink;f.AutoScaleMode=AutoScaleMode.Dpi;f.StartPosition=FormStartPosition.CenterParent;f.MinimumSize=new Size(500,400);try{f.Icon=new Icon(Path.Combine(AppDomain.CurrentDomain.BaseDirectory,"TnDtun.ico"));}catch{}}public static Button Button(string text,EventHandler click,bool primary=false){var b=new Button{Text=text,AutoSize=true,MinimumSize=new Size(100,34),FlatStyle=FlatStyle.Flat,BackColor=primary?Blue:Color.White,ForeColor=primary?Color.White:Ink,Margin=new Padding(4)};b.FlatAppearance.BorderColor=Color.FromArgb(213,221,232);if(click!=null)b.Click+=click;return b;}public static TextBox Edit(string text,bool multi=false){return new TextBox{Text=text??"",Dock=DockStyle.Fill,Multiline=multi,ScrollBars=multi?ScrollBars.Vertical:ScrollBars.None,MaxLength=0,Height=multi?90:28};}public static void Error(IWin32Window owner,Exception e){MessageBox.Show(owner,e.Message,"TnDtun",MessageBoxButtons.OK,MessageBoxIcon.Warning);}public static string Choose(bool save,string filter,string name=""){using(var d=save?(FileDialog)new SaveFileDialog():(FileDialog)new OpenFileDialog()){d.Filter=filter;d.FileName=name;return d.ShowDialog()==DialogResult.OK?d.FileName:null;}}public static string Bytes(long n){if(n<1000)return n+" Б";if(n<1000000)return(n/1000.0).ToString("0.0")+" КБ";if(n<1000000000)return(n/1000000.0).ToString("0.0")+" МБ";return(n/1000000000.0).ToString("0.00")+" ГБ";}}
class Editor:Form {public TableLayoutPanel Grid=new TableLayoutPanel{Dock=DockStyle.Top,AutoSize=true,ColumnCount=2,Padding=new Padding(14)};public FlowLayoutPanel Actions=new FlowLayoutPanel{Dock=DockStyle.Bottom,Height=52,FlowDirection=FlowDirection.RightToLeft,Padding=new Padding(5)};public Editor(string title){Text=title;Style.Form(this);Size=new Size(680,650);Grid.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute,185));Grid.ColumnStyles.Add(new ColumnStyle(SizeType.Percent,100));var scroll=new Panel{Dock=DockStyle.Fill,AutoScroll=true};scroll.Controls.Add(Grid);Controls.Add(scroll);Controls.Add(Actions);Actions.Controls.Add(Style.Button("Отмена",(s,e)=>Close()));}public void Row(string text,Control control,int height=36){int r=Grid.RowCount++;Grid.RowStyles.Add(new RowStyle(SizeType.Absolute,height));Grid.Controls.Add(new Label{Text=text,Dock=DockStyle.Fill,TextAlign=ContentAlignment.MiddleLeft,AutoSize=false},0,r);Grid.Controls.Add(control,1,r);} }
class ProfileEditor:Editor {Rpc rpc;Dictionary<string,object> original;ComboBox mode=new ComboBox{DropDownStyle=ComboBoxStyle.DropDownList,Dock=DockStyle.Fill};Dictionary<string,TextBox> fields=new Dictionary<string,TextBox>();Dictionary<string,object> dns;List<Control> turn=new List<Control>(),awg=new List<Control>(),dnsRows=new List<Control>();public ProfileEditor(Rpc r,object value):base("Профиль подключения"){rpc=r;original=J.Obj(value);dns=J.Obj(J.Get(original,"dns"));mode.Items.AddRange(new object[]{"Amnezia","VK TURN","DNS-туннель"});string m=J.Text(original,"mode");mode.SelectedIndex=m=="turn"?1:m=="dns"?2:0;Row("Режим",mode);Field("title","Название",false,false);Field("amneziaKey","Ключ vpn:// или INI",true,false,awg,150);Field("callLink","Ссылка VK",false,false,turn);Field("server","Сервер : порт",false,false,turn);Field("vlessID","VLESS UUID",false,false,turn);Field("wrapKey","Wrap key",false,true,turn);Field("domain","Домен DNSTT",false,false,dnsRows);Field("publicKey","Публичный ключ",false,false,dnsRows);Field("resolver","DNS-резолвер",false,false,dnsRows);Field("sessionCount","Потоки 1/2/4/8",false,false,dnsRows);Field("tunnelType","Выход socks5 / ssh",false,false,dnsRows);Field("wifiResolver","DNS для Wi-Fi",false,false,dnsRows);var auto=new CheckBox{Text="DNS текущей сети",Checked=J.Get(dns,"autoDetectResolver")==null||J.Bool(dns,"autoDetectResolver"),Dock=DockStyle.Fill};auto.Tag="autoDetectResolver";Row("Автоопределение",auto);dnsRows.Add(auto);var wifi=new CheckBox{Text="Использовать отдельный DNS",Checked=J.Bool(dns,"useWiFiResolver"),Dock=DockStyle.Fill};wifi.Tag="useWiFiResolver";Row("Wi-Fi",wifi);dnsRows.Add(wifi);Field("savedResolvers","Другие DNS, по строке",true,false,dnsRows,75);Field("sshUsername","SSH пользователь",false,false,dnsRows);Field("sshPassword","SSH пароль",false,true,dnsRows);Field("sshPrivateKey","SSH ключ",true,false,dnsRows,90);Field("sshHostKey","SHA256 отпечаток",false,false,dnsRows);mode.SelectedIndexChanged+=(s,e)=>Visibility();Visibility();Actions.Controls.Add(Style.Button("Сохранить",async(s,e)=>{try{var p=new Dictionary<string,object>(original);p["mode"]=new[]{"amnezia","turn","dns"}[mode.SelectedIndex];foreach(var k in new[]{"title","amneziaKey","callLink","server","vlessID","wrapKey"})p[k]=fields[k].Text.Trim();var d=new Dictionary<string,object>(dns);foreach(var k in new[]{"domain","publicKey","resolver","tunnelType","wifiResolver","sshUsername","sshPassword","sshPrivateKey","sshHostKey"})d[k]=fields[k].Text.Trim();int count;if(!int.TryParse(fields["sessionCount"].Text,out count))count=4;d["sessionCount"]=count;d["autoDetectResolver"]=auto.Checked;d["useWiFiResolver"]=wifi.Checked;d["savedResolvers"]=fields["savedResolvers"].Text.Split(new[]{'\r','\n'},StringSplitOptions.RemoveEmptyEntries);p["dns"]=d;await rpc.Call("save_profile",J.D("profile",p));DialogResult=DialogResult.OK;Close();}catch(Exception ex){Style.Error(this,ex);}},true));}
 void Field(string k,string label,bool multi,bool secret,List<Control> list=null,int height=36){bool isDns=list==dnsRows;string v=J.Text(isDns?dns:original,k);if(k=="sessionCount"&&v=="")v="4";if(k=="resolver"&&v=="")v="1.1.1.1:53";if(k=="wifiResolver"&&v=="")v="https://dns.google/dns-query";if(k=="tunnelType"&&v=="")v="socks5";if(k=="savedResolvers")v=string.Join(Environment.NewLine,J.Rows(J.Get(dns,k)).Select(Convert.ToString));var t=Style.Edit(v,multi);if(secret&&!multi)t.UseSystemPasswordChar=true;fields[k]=t;Row(label,t,height);if(list!=null)list.Add(t);}
 void Visibility(){foreach(var list in new[]{turn,awg,dnsRows})foreach(var c in list){bool visible=list==turn?mode.SelectedIndex==1:list==awg?mode.SelectedIndex==0:mode.SelectedIndex==2;c.Visible=visible;int row=Grid.GetRow(c);Grid.GetControlFromPosition(0,row).Visible=visible;Grid.RowStyles[row].Height=visible?(c is TextBox&&((TextBox)c).Multiline?90:36):0;}}
}
class SettingsEditor:Editor {
 readonly Rpc rpc;
 public SettingsEditor(Rpc rpc,object settings,string profileMode):base("Настройки TnDtun"){this.rpc=rpc;var s=J.Obj(settings);var ar=new CheckBox{Text="Автовосстановление · только VK TURN",Checked=J.Bool(s,"autoRecovery"),Dock=DockStyle.Fill};var ipv6=new CheckBox{Text="Разрешить IPv6 через VPN",Checked=J.Bool(s,"ipv6Enabled"),Dock=DockStyle.Fill};var interval=new NumericUpDown{Minimum=15,Maximum=300,Value=Math.Max(15,Math.Min(300,J.Num(s,"turnCheckInterval"))),Dock=DockStyle.Fill};Row("Восстановление",ar);Row("Интервал, секунд",interval);
  var launch=new CheckBox{Text="Подключать последний профиль при запуске",Checked=J.Bool(s,"autoConnectOnLaunch"),Dock=DockStyle.Fill};
  Row("Автоподключение",launch);
  var channelCounts=new[]{1,2,4,10,16};
  var channels=new ComboBox{DropDownStyle=ComboBoxStyle.DropDownList,Dock=DockStyle.Fill};
  channels.Items.AddRange(new object[]{"1","2","4","10 · по умолчанию","16"});
  int channelIndex=Array.IndexOf(channelCounts,(int)J.Num(s,"turnSessionCount"));
  channels.SelectedIndex=channelIndex<0?3:channelIndex;
  Row("Каналы VK TURN",channels);
  Row("Версия",new Label{Text=J.Text(rpc.Last,"version"),Dock=DockStyle.Fill});
Row("IPv6",ipv6);var servers=Style.Edit(string.Join(Environment.NewLine,J.Rows(J.Get(s,"dnsServers")).Select(Convert.ToString)),true);Row("DNS приложения",servers,70);var split=J.Obj(J.Get(s,"splitTunneling"));var choice=new ComboBox{DropDownStyle=ComboBoxStyle.DropDownList,Dock=DockStyle.Fill};choice.Items.AddRange(new object[]{"Весь трафик через VPN","Выбранные адреса без VPN","Только выбранные через VPN"});choice.SelectedIndex=J.Text(split,"mode")=="bypassSelected"?1:J.Text(split,"mode")=="tunnelSelected"?2:0;Row("Сплит-туннель",choice);
  var amneziaSplit=new CheckBox{Text="Использовать списки для Amnezia",
   Checked=J.Get(s,"amneziaSplitEnabled")==null||J.Bool(s,"amneziaSplitEnabled"),Dock=DockStyle.Fill};
  Row("Amnezia",amneziaSplit);
  var restoreValues=new[]{5,15,30,60,0};
  var restoreSplit=new ComboBox{DropDownStyle=ComboBoxStyle.DropDownList,Dock=DockStyle.Fill};
  restoreSplit.Items.AddRange(new object[]{"Через 5 минут","Через 15 минут","Через 30 минут","Через час","При отключении"});
  int restoreIndex=J.Get(s,"fullTunnelMinutes")==null?1:Array.IndexOf(restoreValues,(int)J.Num(s,"fullTunnelMinutes"));
  restoreSplit.SelectedIndex=restoreIndex<0?1:restoreIndex;
  Row("Вернуть сплит-туннель",restoreSplit);
var bypass=Style.Edit(J.Encode(J.Get(split,"bypassEntries")??new object[0]),true);var tunnel=Style.Edit(J.Encode(J.Get(split,"tunnelEntries")??new object[0]),true);Row("Без VPN · JSON или адреса по строке",bypass,130);Row("Через VPN · JSON или адреса по строке",tunnel,130);foreach(var pair in new[]{Tuple.Create("Импорт списка без VPN",bypass),Tuple.Create("Импорт списка через VPN",tunnel)}){var p=pair;var b=Style.Button(p.Item1,async(a,e)=>{var path=Style.Choose(false,"JSON (*.json)|*.json");if(path==null)return;try{p.Item2.Text=J.Encode(await rpc.Call("parse_entries",J.D("path",path)));}catch(Exception ex){Style.Error(this,ex);}});Row("Список",b);}Row("",new Label{Text="Оба списка сохраняются независимо. Изменения применятся после переподключения.",Dock=DockStyle.Fill},60);
  Row("Подключения",Style.Button("Добавить подключение вручную",(sender,e)=>{
   using(var editor=new ProfileEditor(rpc,J.D("mode",profileMode))) editor.ShowDialog(this);
  }));
  var import=Style.Button("Импорт профиля ▾",null);
  var menu=new ContextMenuStrip();
  menu.Items.Add("Из буфера",null,async(sender,e)=>await Import(null,true,false));
  menu.Items.Add("Из файла",null,async(sender,e)=>await Import(null,false,false));
  menu.Items.Add("QR из изображения",null,async(sender,e)=>await Import(null,false,true));
  import.Click+=(sender,e)=>menu.Show(import,0,import.Height);
  Disposed+=(sender,e)=>menu.Dispose();
  Row("",import);
  Actions.Controls.Add(Style.Button("Сохранить",async(a,e)=>{try{Func<TextBox,string> text=box=>box.Text.Trim().StartsWith("[")||box.Text.Trim().StartsWith("{")?box.Text:J.Encode(box.Lines.Where(x=>!string.IsNullOrWhiteSpace(x)).ToArray());var b=await rpc.Call("parse_entries",J.D("text",text(bypass)));var t=await rpc.Call("parse_entries",J.D("text",text(tunnel)));var next=new Dictionary<string,object>(s);next["autoRecovery"]=ar.Checked;next["autoConnectOnLaunch"]=launch.Checked;next["turnSessionCount"]=channelCounts[channels.SelectedIndex];next["amneziaSplitEnabled"]=amneziaSplit.Checked;next["fullTunnelMinutes"]=restoreValues[restoreSplit.SelectedIndex];next["ipv6Enabled"]=ipv6.Checked;next["turnCheckInterval"]=(int)interval.Value;next["dnsServers"]=servers.Lines.Where(x=>!string.IsNullOrWhiteSpace(x)).ToArray();next["splitTunneling"]=J.D("mode",new[]{"disabled","bypassSelected","tunnelSelected"}[choice.SelectedIndex],"bypassEntries",b,"tunnelEntries",t);await rpc.Call("settings",J.D("settings",next));Close();}catch(Exception ex){Style.Error(this,ex);}},true));}
 async Task Import(string value,bool clipboard,bool qr){try{if(clipboard)value=Clipboard.GetText();if(value==null){var path=Style.Choose(false,qr?"Изображения|*.png;*.jpg;*.jpeg;*.gif":"Профили|*.json;*.conf;*.txt|Все файлы|*.*");if(path==null)return;if(qr)value=Convert.ToString(await rpc.Call("qr",J.D("path",path)));else{var p=await rpc.Call("import_profile",J.D("path",path));new ProfileEditor(rpc,p).ShowDialog(this);return;}}if(value.Trim().StartsWith("tndtun:",StringComparison.OrdinalIgnoreCase)){await Subscriptions.Activate(this,rpc,value);return;}var profile=await rpc.Call("import_profile",J.D("text",value));new ProfileEditor(rpc,profile).ShowDialog(this);}catch(Exception e){Style.Error(this,e);}}
}
static class SubscriptionDisplay {
 public static string LocalTime(object subscription) {
  long seconds=J.Num(subscription,"lastSync");
  if(seconds<=0||seconds>253402300799L) return "Ещё не обновлялась";
  return DateTimeOffset.FromUnixTimeSeconds(seconds).ToLocalTime().ToString("dd.MM.yyyy HH:mm");
 }
 public static Label TimeLabel() {
  return new Label{Dock=DockStyle.Fill,Margin=new Padding(4,0,4,0),Font=new Font("Segoe UI",8),AutoEllipsis=true,ForeColor=SystemColors.GrayText,TextAlign=ContentAlignment.MiddleCenter};
 }
 public static Control RefreshBlock(Button button,Label time) {
  var block=new Panel{Dock=DockStyle.Fill,Margin=new Padding(0),Padding=new Padding(4,1,4,0)};
  FillButton(button);
  time.Dock=DockStyle.Bottom;time.Height=17;time.Margin=new Padding(0);
  block.Controls.Add(button);
  block.Controls.Add(time);
  return block;
 }
 public static void FillButton(Button button) {
  button.AutoSize=false;button.MinimumSize=Size.Empty;button.Dock=DockStyle.Fill;
 }
}
class Subscriptions:Form {
 readonly Rpc rpc;
 readonly ListView list=new ListView{Dock=DockStyle.Fill,View=View.Details,FullRowSelect=true,HideSelection=false,MultiSelect=false};
 readonly Label status=new Label{Dock=DockStyle.Bottom,Height=35,Padding=new Padding(10),AutoEllipsis=true};
 readonly Label lastRefresh=SubscriptionDisplay.TimeLabel();
 readonly Button refresh;
 readonly Button refreshAll;
 readonly Action<Dictionary<string,object>> handler;
 object[] rows=new object[0];
 bool busy;
 public Subscriptions(Rpc r) {
  rpc=r;Style.Form(this);Text="Подписки и доступ";Size=new Size(990,485);MinimumSize=new Size(720,400);
  list.Columns.Add("Клиент",155);list.Columns.Add("Код подписки",120);list.Columns.Add("Доступ",180);
  list.Columns.Add("Последнее обновление",165);list.Columns.Add("Режим",95);list.Columns.Add("Сервер",180);
  Controls.Add(list);Controls.Add(status);
  var bar=new TableLayoutPanel{Dock=DockStyle.Top,Height=54,ColumnCount=5,RowCount=1};
  for(int i=0;i<5;i++)bar.ColumnStyles.Add(new ColumnStyle(SizeType.Percent,20));
  bar.RowStyles.Add(new RowStyle(SizeType.Percent,100));
  var activate=Style.Button("Активировать",async(s,e)=>await Activate(this,r,null));
  refresh=Style.Button("Обновить",async(s,e)=>await Work("sync",J.D("id",Selected())));
  refreshAll=Style.Button("Обновить все",async(s,e)=>await Work("sync",J.D()));
  var remove=Style.Button("Удалить",async(s,e)=>{
   string id=Selected();
   if(id!=""&&MessageBox.Show(this,"Удалить подписку и её профили с этого устройства?","TnDtun",MessageBoxButtons.YesNo)==DialogResult.Yes)
    await Work("remove_subscription",J.D("id",id));
  });
  var cancel=Style.Button("Отменить запрос",async(s,e)=>{
   try{await rpc.Call("cancel");}catch(Exception ex){Style.Error(this,ex);}
  });
  foreach(var button in new[]{activate,refreshAll,remove,cancel})SubscriptionDisplay.FillButton(button);
  bar.Controls.Add(activate,0,0);bar.Controls.Add(SubscriptionDisplay.RefreshBlock(refresh,lastRefresh),1,0);
  bar.Controls.Add(refreshAll,2,0);bar.Controls.Add(remove,3,0);bar.Controls.Add(cancel,4,0);
  Controls.Add(bar);
  list.SelectedIndexChanged+=(s,e)=>UpdateRefresh();
  handler=m=>{if(!IsDisposed&&IsHandleCreated)BeginInvoke((Action)(()=>Populate(m)));};
  rpc.State+=handler;FormClosed+=(s,e)=>rpc.State-=handler;
  Populate(r.Last);
 }
 string Selected(){return list.SelectedItems.Count>0?Convert.ToString(list.SelectedItems[0].Tag):"";}
 void UpdateRefresh(){
  string id=Selected();
  var selected=rows.FirstOrDefault(row=>J.Text(row,"id")==id);
  lastRefresh.Text=selected==null?"":SubscriptionDisplay.LocalTime(selected);
  refresh.Enabled=!busy&&selected!=null;
  refreshAll.Enabled=!busy&&rows.Length>0;
 }
 void Populate(object state){
  string selected=Selected();
  rows=J.Rows(J.Get(state,"subscriptions"));
  list.BeginUpdate();
  try{
   for(int i=0;i<rows.Length;i++){
    var sub=rows[i];
    long expiry=J.Num(sub,"expiresAt");
    string access=J.Bool(sub,"needsActivation")?"Нужна активация":J.Text(sub,"status")=="revoked"?"Отозван":
     expiry<=0?"Без срока":expiry<=DateTimeOffset.UtcNow.ToUnixTimeSeconds()?"Истёк":
     expiry<=253402300799L?DateTimeOffset.FromUnixTimeSeconds(expiry).ToLocalTime().ToString("dd.MM.yyyy HH:mm"):"Активна";
    var cells=new[]{J.Text(sub,"name"),J.Text(sub,"activationCode"),access,SubscriptionDisplay.LocalTime(sub),
      J.Bool(sub,"autoSync")?"Авто":"Вручную",J.Text(sub,"server")};
    if(i>=list.Items.Count)list.Items.Add(new ListViewItem(cells));
    var item=list.Items[i];item.Tag=J.Text(sub,"id");
    for(int col=0;col<cells.Length;col++)if(item.SubItems[col].Text!=cells[col])item.SubItems[col].Text=cells[col];
   }
   while(list.Items.Count>rows.Length)list.Items.RemoveAt(list.Items.Count-1);
  }finally{list.EndUpdate();}
  var target=list.Items.Cast<ListViewItem>().FirstOrDefault(item=>Convert.ToString(item.Tag)==selected);
  if(target==null&&list.Items.Count>0)target=list.Items[0];
  if(target!=null&&!target.Selected)target.Selected=true;
  UpdateRefresh();
 }
 async Task Work(string op,object data){
  if(busy)return;
  busy=true;UpdateRefresh();status.Text="Выполняется запрос…";
  try{await rpc.Call(op,data);status.Text="Готово";}
  catch(Exception ex){status.Text="Запрос не выполнен";Style.Error(this,ex);}
  finally{busy=false;if(!IsDisposed)UpdateRefresh();}
 }
 public static async Task Activate(IWin32Window owner,Rpc rpc,string initial){using(var f=new Editor("Активировать доступ")){f.Size=new Size(650,400);var input=Style.Edit(initial??"",true);f.Row("Код или tndtun:// ссылка",input,100);var note=new Label{Text="Введите код администратора или ссылку. Настройки применяются после проверки подписи. Сервер может разрешить автообновление.",Dock=DockStyle.Fill};f.Row("",note,60);var submit=Style.Button("Активировать",null,true);submit.Click+=async(s,e)=>{try{bool confirmed=false;if(input.Text.Trim().StartsWith("tndtun:",StringComparison.OrdinalIgnoreCase)){var u=new Uri(input.Text.Trim());var q=HttpUtility.ParseQueryString(u.Query);if(MessageBox.Show(f,"Сервер: "+q["api"]+"\nКлюч подписи: "+q["key"]+"\n\nДоверять этому серверу и отправить код?","Подтверждение сервера",MessageBoxButtons.YesNo,MessageBoxIcon.Question)!=DialogResult.Yes)return;confirmed=true;}submit.Enabled=false;note.Text="Получаю подписанный пакет…";await rpc.Call("activate",J.D("text",input.Text.Trim(),"confirmed",confirmed));f.DialogResult=DialogResult.OK;f.Close();}catch(Exception ex){Style.Error(f,ex);submit.Enabled=true;note.Text="Данные сохранены. Можно повторить запрос.";}};f.Actions.Controls.Add(submit);f.ShowDialog(owner);}await Task.FromResult(0);}
}
class MainForm:Form {Rpc rpc;ListView profiles=new ListView{Dock=DockStyle.Fill,View=View.Details,FullRowSelect=true,HideSelection=false,MultiSelect=false};Label stateLabel=new Label(),caption=new Label(),metrics=new Label(),message=new Label();
 readonly Label subscriptionTime=SubscriptionDisplay.TimeLabel();
 Button refreshSubscriptions,connectionAction;
 readonly CheckBox fullTunnel=new CheckBox{Text="Всё в туннель",AutoSize=true,Margin=new Padding(4,4,4,4)};
 readonly ToolTip routingTip=new ToolTip();
 bool applyingRouting, requestingRouting;
 bool refreshingSubscriptions;Button primary;NotifyIcon tray;string mode="amnezia";Dictionary<string,object> current=new Dictionary<string,object>();bool exiting,updating,modeLoaded;readonly Dictionary<string,Button> modeButtons=new Dictionary<string,Button>();public MainForm(Rpc r){rpc=r;Text="TnDtun";Style.Form(this);Size=new Size(870,720);MinimumSize=new Size(680,540);var layout=new TableLayoutPanel{Dock=DockStyle.Fill,ColumnCount=1,RowCount=7,Padding=new Padding(18)};layout.RowStyles.Add(new RowStyle(SizeType.Absolute,60));layout.RowStyles.Add(new RowStyle(SizeType.Absolute,48));layout.RowStyles.Add(new RowStyle(SizeType.Absolute,142));layout.RowStyles.Add(new RowStyle(SizeType.Absolute,48));layout.RowStyles.Add(new RowStyle(SizeType.Percent,100));layout.RowStyles.Add(new RowStyle(SizeType.Absolute,48));layout.RowStyles.Add(new RowStyle(SizeType.Absolute,52));var title=new Label{Text="TnDtun",Font=new Font("Segoe UI",25,FontStyle.Bold),ForeColor=Style.Navy,Dock=DockStyle.Fill};layout.Controls.Add(title,0,0);
 var access=new TableLayoutPanel{Dock=DockStyle.Fill,ColumnCount=3,RowCount=1,Margin=new Padding(0,0,0,3)};
 foreach(float width in new[]{35f,35f,30f})access.ColumnStyles.Add(new ColumnStyle(SizeType.Percent,width));
 access.RowStyles.Add(new RowStyle(SizeType.Percent,100));
 var subscriptions=Style.Button("Подписки",(sender,e)=>{using(var dialog=new Subscriptions(rpc))dialog.ShowDialog(this);});
 SubscriptionDisplay.FillButton(subscriptions);
 refreshSubscriptions=Style.Button("Обновить",async(sender,e)=>await RefreshSubscriptions());
 var settings=Style.Button("Настройки",(sender,e)=>{using(var editor=new SettingsEditor(rpc,J.Get(current,"settings"),mode))editor.ShowDialog(this);});
 SubscriptionDisplay.FillButton(settings);
 access.Controls.Add(subscriptions,0,0);
 access.Controls.Add(SubscriptionDisplay.RefreshBlock(refreshSubscriptions,subscriptionTime),1,0);
 access.Controls.Add(settings,2,0);
 layout.Controls.Add(access,0,1);
var modes=new FlowLayoutPanel{Dock=DockStyle.Fill};foreach(var pair in new[]{Tuple.Create("Amnezia","amnezia"),Tuple.Create("VK TURN","turn"),Tuple.Create("DNS-туннель","dns")}){var p=pair;var button=Style.Button(p.Item1,async(s,e)=>{mode=p.Item2;modeLoaded=true;Apply(current);try{await rpc.Call("mode",J.D("text",mode));}catch(Exception ex){Style.Error(this,ex);}});modeButtons[p.Item2]=button;modes.Controls.Add(button);}layout.Controls.Add(modes,0,3);profiles.OwnerDraw=true;profiles.DrawColumnHeader+=(s,e)=>e.DrawDefault=true;profiles.DrawSubItem+=DrawProfileCell;var card=new TableLayoutPanel{Dock=DockStyle.Fill,BackColor=Color.White,Padding=new Padding(12),ColumnCount=2,RowCount=1};
 card.ColumnStyles.Add(new ColumnStyle(SizeType.Percent,100));
 card.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute,170));
 card.RowStyles.Add(new RowStyle(SizeType.Percent,100));
 var statusRows=new TableLayoutPanel{Dock=DockStyle.Fill,Margin=new Padding(0),ColumnCount=1,RowCount=4};
 statusRows.RowStyles.Add(new RowStyle(SizeType.Absolute,35));
 statusRows.RowStyles.Add(new RowStyle(SizeType.Absolute,22));
 statusRows.RowStyles.Add(new RowStyle(SizeType.Absolute,22));
 statusRows.RowStyles.Add(new RowStyle(SizeType.Percent,100));
 card.Controls.Add(statusRows,0,0);
 var buttons=new TableLayoutPanel{Dock=DockStyle.Fill,Margin=new Padding(0),ColumnCount=1,RowCount=2};
 buttons.RowStyles.Add(new RowStyle(SizeType.Percent,65));
 buttons.RowStyles.Add(new RowStyle(SizeType.Percent,35));
 card.Controls.Add(buttons,1,0);
 stateLabel.Font=new Font("Segoe UI",16,FontStyle.Bold);
 stateLabel.AutoEllipsis=true;
 stateLabel.TextAlign=ContentAlignment.MiddleLeft;
 stateLabel.Dock=caption.Dock=metrics.Dock=message.Dock=DockStyle.Fill;
 caption.AutoEllipsis=true;
 message.ForeColor=Color.FromArgb(157,72,28);
 message.AutoEllipsis=true;
 statusRows.Controls.Add(stateLabel,0,0);
 statusRows.Controls.Add(caption,0,1);
 statusRows.Controls.Add(metrics,0,2);
 statusRows.Controls.Add(message,0,3);
 primary=Style.Button("Подключить",async(s,e)=>{try{var phase=J.Text(current,"phase");if(phase=="disconnected"||phase=="")await rpc.Call("connect",J.D("id",Selected()));else await rpc.Call("stop");}catch(Exception ex){Style.Error(this,ex);}},true);SubscriptionDisplay.FillButton(primary);buttons.Controls.Add(primary,0,0);connectionAction=Style.Button("Проверить VK",async(sender,e)=>{
  try {
   if(J.Bool(current,"captcha")) Process.Start(new ProcessStartInfo("explorer.exe","http://localhost:8765/"){UseShellExecute=true});
   else await rpc.Call("reconnect_active");
  }catch(Exception error){Style.Error(this,error);}
 });
 var routingActions = new Panel{Dock=DockStyle.Fill,Margin=new Padding(0)};
 connectionAction.Dock=DockStyle.Fill; connectionAction.AutoSize=false; connectionAction.MinimumSize=Size.Empty;
 fullTunnel.Dock=DockStyle.Fill;
 routingActions.Controls.Add(connectionAction);
 routingActions.Controls.Add(fullTunnel);
 fullTunnel.CheckedChanged+=async(sender,e)=>await SetTemporaryRouting();
 Disposed+=(sender,e)=>routingTip.Dispose();
 buttons.Controls.Add(routingActions,0,1);layout.Controls.Add(card,0,2);profiles.Columns.Add("Профиль",360);profiles.Columns.Add("Источник",150);profiles.Columns.Add("Доступ",100);profiles.SelectedIndexChanged+=async(s,e)=>{if(updating||Selected()=="")return;try{await rpc.Call("select",J.D("id",Selected()));}catch(Exception ex){Style.Error(this,ex);}};profiles.DoubleClick+=async(s,e)=>await EditProfile();layout.Controls.Add(profiles,0,4);var edit=new FlowLayoutPanel{Dock=DockStyle.Fill};edit.Controls.Add(Style.Button("Изменить",async(s,e)=>await EditProfile()));edit.Controls.Add(Style.Button("Удалить",async(s,e)=>{if(Selected()==""||MessageBox.Show(this,"Удалить выбранный профиль?","TnDtun",MessageBoxButtons.YesNo)!=DialogResult.Yes)return;try{await rpc.Call("delete_profile",J.D("id",Selected()));}catch(Exception ex){Style.Error(this,ex);}}));layout.Controls.Add(edit,0,5);var actions=new FlowLayoutPanel{Dock=DockStyle.Fill};actions.Controls.Add(Style.Button("Экспорт копии",async(s,e)=>{var path=Style.Choose(true,"JSON (*.json)|*.json","TnDtun-backup-"+DateTime.Now.ToString("yyyy-MM-dd")+".json");if(path==null)return;if(MessageBox.Show(this,"Копия содержит приватные ключи. Сохранить её в выбранный файл?","TnDtun",MessageBoxButtons.YesNo,MessageBoxIcon.Warning)!=DialogResult.Yes)return;try{await rpc.Call("export",J.D("path",path));MessageBox.Show(this,"Копия сохранена.","TnDtun");}catch(Exception ex){Style.Error(this,ex);}}));actions.Controls.Add(Style.Button("Импорт копии",async(s,e)=>{var path=Style.Choose(false,"JSON (*.json)|*.json");if(path==null||MessageBox.Show(this,"Заменить профили и настройки? VPN отключится. Подписки потребуется активировать заново.","TnDtun",MessageBoxButtons.YesNo,MessageBoxIcon.Warning)!=DialogResult.Yes)return;try{await rpc.Call("import",J.D("path",path,"confirmed",true));}catch(Exception ex){Style.Error(this,ex);}}));layout.Controls.Add(actions,0,6);Controls.Add(layout);tray=new NotifyIcon{Icon=Icon,Text="TnDtun",Visible=true};tray.DoubleClick+=(s,e)=>Restore();var tm=new ContextMenuStrip();tm.Items.Add("Открыть",null,(s,e)=>Restore());tm.Items.Add("Отключить",null,async(s,e)=>{try{await rpc.Call("stop");}catch{}});tm.Items.Add("Выход",null,async(s,e)=>await Exit());tray.ContextMenuStrip=tm;rpc.State+=m=>{if(!IsDisposed&&IsHandleCreated)BeginInvoke((Action)(()=>Apply(m)));};rpc.Fatal+=error=>{if(!IsDisposed&&IsHandleCreated)BeginInvoke((Action)(()=>{current["phase"]="disconnected";current["message"]=error;Apply(current);}));};Shown+=async(s,e)=>{try{Apply(J.Obj(await rpc.Call("state")));if(rpc.TestHome==null&&J.Bool(J.Get(current,"settings"),"autoConnectOnLaunch"))await rpc.Call("connect_saved");}catch(Exception ex){Style.Error(this,ex);}};FormClosing+=(s,e)=>{if(!exiting&&e.CloseReason==CloseReason.UserClosing){e.Cancel=true;Hide();}};Activated+=async(s,e)=>{try{await rpc.Call("sync_wake");}catch{}};
 Apply(r.Last);}
 public void ShowMode(string value){mode=value;modeLoaded=true;Apply(current);}public void Restore(){Show();WindowState=FormWindowState.Normal;Activate();}string Selected(){return profiles.SelectedItems.Count>0?Convert.ToString(profiles.SelectedItems[0].Tag):"";}public void Apply(Dictionary<string,object> m){current=m;if(!modeLoaded&&J.Text(m,"mode")!=""){mode=J.Text(m,"mode");modeLoaded=true;}foreach(var pair in modeButtons){pair.Value.BackColor=pair.Key==mode?Style.Blue:Color.White;pair.Value.ForeColor=pair.Key==mode?Color.White:Style.Ink;}RefreshProfiles(m);var subscriptions=J.Rows(J.Get(m,"subscriptions"));
 var latest=subscriptions.OrderByDescending(sub=>J.Num(sub,"lastSync")).FirstOrDefault();
 subscriptionTime.Text=latest==null?"":SubscriptionDisplay.LocalTime(latest);
 refreshSubscriptions.Enabled=!refreshingSubscriptions&&subscriptions.Length>0;
 string phase=J.Text(m,"phase");var names=new Dictionary<string,string>{{"preparing","Подготовка"},{"connecting","Подключение…"},{"connected","Подключено"},{"recovering","Восстановление…"},{"disconnecting","Отключение…"},{"switching_routes","Применение маршрутов…"},{"waiting_network","Жду сеть…"},{"retry_wait","Ожидание восстановления…"}};stateLabel.Text=names.ContainsKey(phase)?names[phase]:"Отключено";
 bool captcha=J.Bool(m,"captcha");
 bool reconnect=phase=="connected"&&J.Bool(m,"reconnectRecommended");
 connectionAction.Text=captcha?"Проверить VK":"Переподключить";
 connectionAction.Visible=captcha||reconnect;
 applyingRouting=true;
 try{
  fullTunnel.Visible=J.Bool(m,"fullTunnelSupported")&&!captcha&&!reconnect;
  fullTunnel.Enabled=phase=="connected"&&!J.Bool(m,"routingPending")&&!requestingRouting;
  fullTunnel.Checked=J.Bool(m,"temporaryFullTunnel");
  long expiry=J.Num(m,"fullTunnelUntil");
  string help=!fullTunnel.Checked?"Временно отправлять весь интернет-трафик через VPN":
   expiry>0?"Возврат сплит-туннеля в "+DateTimeOffset.FromUnixTimeSeconds(expiry).ToLocalTime().ToString("HH:mm"):
   "Сплит-туннель вернётся при отключении";
  if(routingTip.GetToolTip(fullTunnel)!=help)routingTip.SetToolTip(fullTunnel,help);
 }finally{applyingRouting=false;}

 primary.Text=phase=="disconnected"||phase==""?"Подключить":"Отключить";primary.Enabled=phase!="disconnecting"&&(Selected()!=""||phase!="disconnected"&&phase!="");caption.Text="Профиль: "+J.Rows(J.Get(m,"profiles")).Where(p=>J.Text(p,"id")== (J.Text(m,"active")!=""?J.Text(m,"active"):Selected())).Select(p=>J.Text(p,"title")).FirstOrDefault();metrics.AutoEllipsis=true;
 metrics.Text="↓ "+Style.Bytes(J.Num(m,"downRate"))+"/с    ↑ "+Style.Bytes(J.Num(m,"upRate"))+
  "/с    Всего "+Style.Bytes(J.Num(m,"up")+J.Num(m,"down"))+"    "+(J.Num(m,"latency")>0?J.Num(m,"latency")+" мс":"— мс");message.Text=profiles.Items.Count==0?"Откройте «Подписки», чтобы добавить подключения.":J.Bool(m,"captcha")?"Требуется проверка VK — нажмите «Проверить VK»":reconnect?"Переподключитесь, чтобы применить изменения.":J.Text(m,"message");tray.Text="TnDtun · "+stateLabel.Text;}
 async Task SetTemporaryRouting(){
  if(applyingRouting||requestingRouting)return;
  requestingRouting=true;fullTunnel.Enabled=false;
  try{await rpc.Call("temporary_full_tunnel",J.D("enabled",fullTunnel.Checked));}
  catch(Exception error){
   if(!IsDisposed)Style.Error(this,error);
  }finally{
   requestingRouting=false;
   if(!IsDisposed)Apply(rpc.Last);
  }
 }
 async Task RefreshSubscriptions(){
  if(refreshingSubscriptions)return;
  refreshingSubscriptions=true;refreshSubscriptions.Enabled=false;
  refreshSubscriptions.Text="Обновление…";
  try{await rpc.Call("sync");}
  catch(Exception error){Style.Error(this,error);}
  finally{
   refreshingSubscriptions=false;refreshSubscriptions.Text="Обновить";
   refreshSubscriptions.Enabled=J.Rows(J.Get(current,"subscriptions")).Length>0;
  }
 }
 void DrawProfileCell(object sender,DrawListViewSubItemEventArgs e){
  bool selected=e.Item.Selected;
  using(var background=new SolidBrush(selected?Style.Blue:profiles.BackColor))e.Graphics.FillRectangle(background,e.Bounds);
  var bounds=e.Bounds;bounds.Inflate(-4,0);
  TextRenderer.DrawText(e.Graphics,e.SubItem.Text,profiles.Font,bounds,selected?Color.White:profiles.ForeColor,TextFormatFlags.SingleLine|TextFormatFlags.VerticalCenter|TextFormatFlags.EndEllipsis|TextFormatFlags.NoPrefix);
 }
 void RefreshProfiles(Dictionary<string,object> state){
  var rows=J.Rows(J.Get(state,"profiles")).Where(p=>J.Text(p,"mode")==mode).ToArray();
  string selected=Selected();if(selected=="")selected=J.Text(state,"selected");
  if(!rows.Any(p=>J.Text(p,"id")==selected))selected=rows.Length>0?J.Text(rows[0],"id"):"";
  updating=true;
  try{
   profiles.BeginUpdate();
   try{
    for(int i=0;i<rows.Length;i++){
     var p=rows[i];var cells=new[]{J.Text(p,"title"),J.Bool(p,"managed")?"Подписка":J.Text(p,"id")=="tndtun.builtin.dns.v1"?"Встроенный":"Ручной",J.Bool(p,"expired")?"Истёк":""};
     if(i>=profiles.Items.Count)profiles.Items.Add(new ListViewItem(cells));
     var item=profiles.Items[i];item.Tag=J.Text(p,"id");
     for(int column=0;column<cells.Length;column++)if(item.SubItems[column].Text!=cells[column])item.SubItems[column].Text=cells[column];
    }
    while(profiles.Items.Count>rows.Length)profiles.Items.RemoveAt(profiles.Items.Count-1);
   }finally{profiles.EndUpdate();}
   foreach(ListViewItem item in profiles.Items){bool chosen=Convert.ToString(item.Tag)==selected;if(item.Selected!=chosen)item.Selected=chosen;}
  }finally{updating=false;}
 }
 async Task EditProfile(){if(Selected()=="")return;try{var p=await rpc.Call("profile",J.D("id",Selected()));if(J.Text(p,"id")=="tndtun.builtin.dns.v1"||J.Text(p,"subscriptionID")!=""){MessageBox.Show(this,"Встроенный профиль и профили подписки изменяются из своего источника.","TnDtun");return;}new ProfileEditor(rpc,p).ShowDialog(this);}catch(Exception e){Style.Error(this,e);}}
 public async Task Exit(){if(exiting)return;exiting=true;Enabled=false;try{await rpc.Call("stop");}catch{}await Task.Run(()=>rpc.Dispose());tray.Dispose();Close();Application.Exit();}
}
static class Instance {
 static string Name {get{return "TnDtun-"+WindowsIdentity.GetCurrent().User.Value+"-"+Process.GetCurrentProcess().SessionId;}}
 public static void Forward(string[] args){try{using(var pipe=new NamedPipeClientStream(".",Name,PipeDirection.Out)){pipe.Connect(3000);using(var w=new StreamWriter(pipe,new UTF8Encoding(false))){w.WriteLine(J.Encode(J.D("activation",args.Length==2&&args[0]=="--activate"?args[1]:"")));}}}catch{MessageBox.Show("Не удалось открыть запущенное окно. Откройте TnDtun из области уведомлений.","TnDtun");}}
 public static void Listen(MainForm f,Rpc rpc){var thread=new Thread(()=>{while(!f.IsDisposed){try{var security=new PipeSecurity();security.SetAccessRuleProtection(true,false);security.AddAccessRule(new PipeAccessRule(WindowsIdentity.GetCurrent().User,PipeAccessRights.FullControl,System.Security.AccessControl.AccessControlType.Allow));using(var pipe=new NamedPipeServerStream(Name,PipeDirection.In,1,PipeTransmissionMode.Byte,PipeOptions.None,8192,8192,security)){pipe.WaitForConnection();using(var reader=new StreamReader(pipe,Encoding.UTF8)){var chars=new List<char>();while(chars.Count<=16384){int c=reader.Read();if(c<0||c=='\n')break;chars.Add((char)c);}if(chars.Count>16384)continue;var value=J.New().DeserializeObject(new string(chars.ToArray()));string activation=J.Text(value,"activation");if(!f.IsDisposed&&f.IsHandleCreated)f.BeginInvoke((Action)(async()=>{f.Restore();if(activation!="")await Subscriptions.Activate(f,rpc,activation);}));}}}catch{if(f.IsDisposed)return;Thread.Sleep(250);}}});thread.IsBackground=true;thread.Start();}
}
static class Program {static void Capture(Form f,string path){f.Refresh();using(var b=new Bitmap(f.Width,f.Height)){f.DrawToBitmap(b,new Rectangle(Point.Empty,b.Size));b.Save(path);}} [STAThread]static void Main(string[] args){Application.EnableVisualStyles();Application.SetCompatibleTextRenderingDefault(false);using(var rpc=new Rpc()){if(args.Length==2&&args[0]=="--smoke"){rpc.TestHome=Path.Combine(args[1],"isolated-state");using(var f=new MainForm(rpc)){var timer=new System.Windows.Forms.Timer{Interval=2500};timer.Tick+=(s,e)=>{timer.Stop();try{Directory.CreateDirectory(args[1]);using(var bmp=new Bitmap(f.Width,f.Height)){f.DrawToBitmap(bmp,new Rectangle(Point.Empty,bmp.Size));bmp.Save(Path.Combine(args[1],"TnDtun-main.png"));}foreach(var value in new[]{"turn","dns"}){f.ShowMode(value);Capture(f,Path.Combine(args[1],"TnDtun-"+value+".png"));}using(var editor=new SettingsEditor(rpc,J.Get(rpc.Last,"settings"),J.Text(rpc.Last,"mode"))){editor.Show();Capture(editor,Path.Combine(args[1],"TnDtun-settings.png"));editor.Close();}using(var editor=new ProfileEditor(rpc,J.D("mode","dns"))){editor.Show();Capture(editor,Path.Combine(args[1],"TnDtun-profile.png"));editor.Close();}File.WriteAllText(Path.Combine(args[1],"ui-smoke.json"),J.Encode(rpc.Last),Encoding.UTF8);}finally{rpc.Dispose();Environment.Exit(0);}};timer.Start();Application.Run(f);}return;}bool first;using(var mutex=new Mutex(true,"Local\\TnDtun-"+WindowsIdentity.GetCurrent().User.Value,out first)){if(!first){Instance.Forward(args);return;}using(var f=new MainForm(rpc)){Instance.Listen(f,rpc);if(args.Length==2&&args[0]=="--activate")f.Shown+=async(s,e)=>await Subscriptions.Activate(f,rpc,args[1]);Application.Run(f);}}}}
}
}
