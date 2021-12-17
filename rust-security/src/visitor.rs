//! provide [CountStruct]
//! impl visitor
//! provide [get_span_lines] function
use rustc_ast::ast::{
    AnonConst, Arm, AssocItem, AssocTyConstraint, Async, AttrKind, Attribute, Block,
    BlockCheckMode, Const, EnumDef, Expr, ExprKind, FnHeader, FnRetTy, ForeignItem, GenericArg,
    GenericArgs, GenericBound, GenericParam, Generics, Item, ItemKind, Label, Lifetime,
    Local, MacCall, MacroDef, Param, Pat, PatKind, Path, PathSegment, PolyTraitRef, Stmt,
    TraitBoundModifier, TraitRef, Ty, TyKind, Unsafe, UseTree, Variant, VariantData, Visibility,
    WherePredicate,BinOpKind,StmtKind,
};
use rustc_ast::node_id::NodeId;
use rustc_ast::visit::{
    self, walk_anon_const, walk_arm, walk_assoc_item, walk_assoc_ty_constraint, walk_attribute,
    walk_block, walk_enum_def, walk_expr, walk_fn, walk_fn_ret_ty, walk_foreign_item,
    walk_generic_arg, walk_generic_args, walk_generic_param, walk_generics,
    walk_ident, walk_item, walk_label, walk_lifetime, walk_local, walk_mac, walk_param,
    walk_param_bound, walk_pat, walk_path, walk_path_segment, walk_poly_trait_ref, walk_stmt,
    walk_struct_def, walk_trait_ref, walk_ty, walk_use_tree, walk_variant, walk_vis,
    walk_where_predicate, AssocCtxt, FnKind,
};
use rustc_span::{
    source_map::SourceMap,
    symbol::{Ident, Symbol},
    Span,
};

use std::fs::File;
use std::fs::OpenOptions;
use std::io::Write;

pub struct BOStruct<'a> {
    pub file_name: String,
    pub is_unsafe: bool,  // 表示是否unsafe块
    pub is_index: bool,   // 表示是否数组类变量
    pub is_def: bool,     // 表示变量是否初次定义
    pub temp: [String; 2],  // 表示是否需要根据自定义pattern过滤定义的变量
    pub def_list: Vec<String>, // 表示定义变量列表
    pub use_list: Vec<String>, // 表示使用变量列表
    pub times: i32,            // 表示遍历次数
    pub localleft: bool,

    

    /// The source_map is necessary to go from a `Span` to actual line & column numbers for closures.
    pub source_map: &'a SourceMap,
    pub line: i32,
    //erroe_log_file
    pub error_log_file_path: &'a String,
}

impl<'a> BOStruct<'a> {
    
}

/// impl visitor
impl<'ast, 'a> visit::Visitor<'ast> for BOStruct<'a> {
    fn visit_item(&mut self, i: &'ast Item) {
        println!("{:#?}", i);
        println!("module test");
        println!();
        print!("let ");
        walk_item(self, i)
    }
    fn visit_fn(&mut self, fk: FnKind<'ast>, s: Span, _: NodeId) {
        
        // 第一遍遍历函数AST，获取在unsafe块中使用的数组类变量列表
        self.def_list = Vec::new();
        self.use_list = Vec::new();

        self.times += 1;

        match fk {
            FnKind::Fn(ref ctx,ref ident ,ref sig, ref vis, ref blo ) => {
                
                print!("(");
                let mut pat_temp = &sig.decl.inputs[0].pat;//第一个参数
                match pat_temp.kind{
                    PatKind::Ident(ref mode, ref ident, ref option) => {
                        self.visit_ident(*ident);//打印出第一个参数的类型
                    }
                    _ => {}
                }
                print!(": ");
                let mut ty_temp = &sig.decl.inputs[0].ty;//第一个参数的类型
                
                match ty_temp.kind{
                    TyKind::Path(_, ref path) => {
                        self.visit_path_segment(path.span, &path.segments[0]);//打印出第一个参数的类型
                    }
                    _ => {}
                }
                print!(")");
                print!(" ");
                print!("(");
                let pat_temp = &sig.decl.inputs[1].pat;//第2个参数
                match pat_temp.kind{
                    PatKind::Ident(ref mode, ref ident, ref option) => {
                        self.visit_ident(*ident);//打印出第2个参数的类型
                    }
                    _ => {}
                }
                print!(": ");
                let ty_temp = &sig.decl.inputs[1].ty;//第2个参数的类型
                match ty_temp.kind{
                    TyKind::Path(_, ref path) => {
                        self.visit_path_segment(path.span, &path.segments[0]);//打印出第2个参数的类型
                    }
                    _ => {}
                }
                print!(")");
                //打印返回值类型
                print!(" : ");
                let out_prama = &sig.decl.output;
                match out_prama{
                    FnRetTy::Ty(ref ty) => {
                        match ty.kind {
                            TyKind::Path(_, ref path) =>{
                                self.visit_path_segment(path.span, &path.segments[0]);
                            }
                            _ => {}
                        }
                    }
                    _ => {}
                }
                //打印函数体
                //TODO 在visit_block 中实现
                print!(" = ");
                match blo{
                    Some(ref b)=>{
                        let statement = &b.stmts[0];
                        match statement.kind{
                            StmtKind::Expr(ref exp)=>{
                                self.visit_expr(&exp);
                            }
                            _ =>{}
                        }
                    }
                    _ =>{}
                }

            }
            _ =>{}
        }
        //walk_fn(self, fk, s);
    }
    fn visit_block(&mut self, b: &'ast Block) {
        walk_block(self, b);
    }
    fn visit_stmt(&mut self, s: &'ast Stmt) {
        walk_stmt(self, s)
    }
    fn visit_local(&mut self, l: &'ast Local) {
        walk_local(self, l);
    }
    fn visit_expr(&mut self, ex: &'ast Expr) {
        match ex.kind {
            ExprKind::Assign(..) => {

            }
            ExprKind::Path(_,ref p) => {
                let mut vec = &p.segments;
                //println!("{:#?}", vec);

            }
            ExprKind::Lit(..) => {

            }
            ExprKind::Binary(ref op, ref lv, ref rv) => {
                match op.node{
                    BinOpKind::Add => { }
                    BinOpKind::Sub => { }
                    BinOpKind::Mul => { }
                    BinOpKind::Div => { 

                        match lv.kind {
                            ExprKind::Path(_, ref path) =>{
                                self.visit_path_segment(path.span, &path.segments[0]);
                            }
                            _ => {}
                        }
                        print!("/ ");
                        match rv.kind {
                            ExprKind::Path(_, ref path) =>{
                                self.visit_path_segment(path.span, &path.segments[0]);
                            }
                            _ => {}
                        }
                    }
                    BinOpKind::Rem => { }
                    BinOpKind::Shl => { }
                    BinOpKind::Shr => { }
                    _ => {  }
                }
                let error_content = format!("File: {}, Error:: variable '{}' in Line {}.\n", 
                                                    self.file_name, self.temp[0], self.temp[1]);
                println!("{}", error_content);
                write_error_log(self.error_log_file_path, error_content);
                self.temp = ["".to_string(), "".to_string()];
                    
                
            }
            ExprKind::Index(..) => {
                self.is_index = true;
            }
            ExprKind::Call(ref func, ref params) => {
                println!()
            }
            _ => (),
        }
        //walk_expr(self, ex);
    }
    fn visit_ident(&mut self, ident: Ident) {


        let var: String = (ident.name.as_str()).to_string();
        if var == "i32"{
            let result2 = str::replace(&var, "i32", "int");
            print!("{} ", result2);
        }else{
            print!("{} ",var);
        }

        //print!("{}  ",var);
        
    }
    fn visit_param(&mut self, param: &'ast Param) {
        walk_param(self, param)
    }
    fn visit_path(&mut self, _path: &'ast Path, _id: NodeId) {
        walk_path(self, _path);
    }
    fn visit_path_segment(&mut self, _path_span: Span, _path_segment: &'ast PathSegment) {
        //println!("{:#?}", _path_segment.ident);
        let var: String = (_path_segment.ident.name.as_str()).to_string();
        //let mut result = str::replace(&var, "#0", "");
        if var == "i32"{
            let result2 = str::replace(&var, "i32", "int");
            print!("{} ", result2);
        }else{
            print!("{} ",var);
        }
        
        //walk_path_segment(self, _path_span, _path_segment);
    }
    fn visit_pat(&mut self, p: &'ast Pat) {
        walk_pat(self, p)
    }
    fn visit_expr_post(&mut self, _ex: &'ast Expr) {
        // Nothing to do.
    }
    fn visit_ty(&mut self, _t: &'ast Ty) {
        // Nothing to do.
    }
    fn visit_name(&mut self, _span: Span, _name: Symbol) {
        // Nothing to do.
    }
    fn visit_foreign_item(&mut self, _i: &'ast ForeignItem) {
        // Nothing to do.
    }
    fn visit_arm(&mut self, _a: &'ast Arm) {
        // Nothing to do
    }
    fn visit_anon_const(&mut self, _c: &'ast AnonConst) {
        // Nothing to do
    }
    fn visit_enum_def(
        &mut self,
        _enum_definition: &'ast EnumDef,
        _generics: &'ast Generics,
        _item_id: NodeId,
        _: Span,
    ) {
        // Nothing to do
    }
    fn visit_variant(&mut self, _v: &'ast Variant) {
        // Nothing to do
    }
    fn visit_label(&mut self, _label: &'ast Label) {
        // Nothing to do
    }
    fn visit_lifetime(&mut self, _lifetime: &'ast Lifetime) {
        // Nothing to do
    }
    fn visit_mac_call(&mut self, _mac: &'ast MacCall) {
        // Nothing to do
    }
    fn visit_mac_def(&mut self, _mac: &'ast MacroDef, _id: NodeId) {
        // Nothing to do
    }
    fn visit_use_tree(&mut self, _use_tree: &'ast UseTree, _id: NodeId, _nested: bool) {
        // Nothing to do
    }
    fn visit_generic_args(&mut self, _path_span: Span, _generic_args: &'ast GenericArgs) {
        // Nothing to do
        println!("args");

    }
    fn visit_generic_arg(&mut self, _generic_arg: &'ast GenericArg) {
        // Nothing to do
    }
    fn visit_assoc_ty_constraint(&mut self, _constraint: &'ast AssocTyConstraint) {
        // Nothing to do
    }
    fn visit_attribute(&mut self, _attr: &'ast Attribute) {
        // Nothing to do
    }
    fn visit_vis(&mut self, _vis: &'ast Visibility) {
        // Nothing to do
    }
    fn visit_fn_ret_ty(&mut self, _ret_ty: &'ast FnRetTy) {
        // Nothing to do
    }
    fn visit_fn_header(&mut self, _header: &'ast FnHeader) {
        // Nothing to do
    }
    fn visit_assoc_item(&mut self, _i: &'ast AssocItem, _ctxt: AssocCtxt) {
        // Nothing to do
    }
    fn visit_trait_ref(&mut self, _t: &'ast TraitRef) {
        // Nothing to do
    }
    fn visit_param_bound(&mut self, _bounds: &'ast GenericBound) {
        // Nothing to do
    }
    fn visit_poly_trait_ref(&mut self, _t: &'ast PolyTraitRef, _m: &'ast TraitBoundModifier) {
        // Nothing to do
    }
    fn visit_variant_data(&mut self, _s: &'ast VariantData) {
        // Nothing to do
    }
    fn visit_generic_param(&mut self, _param: &'ast GenericParam) {
        // Nothing to do
    }
    fn visit_generics(&mut self, _g: &'ast Generics) {
        // Nothing to do
    }
    fn visit_where_predicate(&mut self, _p: &'ast WherePredicate) {
        // Nothing to do
    }
}

fn contain_var<T: PartialEq>(var_list: &Vec<T>, var: &T) -> bool {
    for x in var_list {
        if *x == *var {
            return true;
        }
    }
    false
}
fn print_var(var_list: &Vec<String>) {
    for x in var_list {
        println!("{}",*x);
    }
}

fn write_error_log(error_log_file_path: &String, content: String) {
    let mut f = OpenOptions::new().append(true).open(error_log_file_path.to_string()).expect("cannot open file");
    f.write_all(content.as_bytes()).expect("write failed");
}
